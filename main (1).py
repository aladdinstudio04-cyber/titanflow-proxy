# -----------------------------------------------------------------------------
# TitanFlow Data API - main.py
# Enterprise-grade, Multi-tenant, SaaS-ready, Global Commerce Scale
# Author: TitanFlow Engineering
# Version: 2.0.0
#
# v2.0.0 - "Atlas" Release (major upgrade)
# -----------------------------------------------------------------------------
# SCRAPING POWER
#   * Anti-bot evasion: rotating browser fingerprints (UA + client
#     hints + Accept-Language pools), per-attempt header rotation
#   * Bot-challenge / CAPTCHA detection with automatic identity
#     rotation and retry
#   * Smart retries: jittered exponential backoff, Retry-After
#     honoring on 429/503, per-domain circuit breaker
#   * Optional upstream proxy support (SCRAPER_PROXY_URL)
#   * Connection pooling via a shared HTTP/2-capable client
#   * Deep extraction: JSON-LD (schema.org) engine + per-platform CSS
#     engines -> brand, seller, features, breadcrumbs, image galleries,
#     ratings, review counts, stock, discounts, currency detection
# 
# 
# PLATFORM COVERAGE (8 platforms, 40+ domains)
#   * Amazon (all 28 storefronts + 18 shortlink domains, ASIN
#     canonicalization, affiliate-tag preservation)
#   * Flipkart - Meesho - eBay (global storefronts) - Walmart
#   * AliExpress - Myntra - Ajio
# 
# ENTERPRISE INFRASTRUCTURE
#   * In-process TTL+LRU response cache (per-URL, bypass via fresh=true)
#   * Async batch job queue: POST /v1/batch -> job id -> poll results
#   * Usage analytics per client: platform mix, latency, cache ratio
#   * Multi-tier plans: FREE / PRO / ENTERPRISE (quota, rate, batch size)
#   * Idempotent Stripe webhooks (event-id dedup store)
#   * Request-ID tracing, process-time headers, GZip compression
#   * /metrics operational endpoint, hardened /health probe
# 
# SECURITY HARDENING
#   * Constant-time API-key & admin-secret comparison (hmac.compare_digest)
#   * API keys never logged (masked suffix only)
#   * Stripe signatures verified on the raw body (official SDK)
#   * Per-API-key rate limiting (falls back to client IP)
# 
# BACKWARD COMPATIBILITY
#   * Identical env var names: SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY,
#     STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET, STRIPE_PRO_PRICE_ID,
#     STRIPE_CHECKOUT_URL, ADMIN_SECRET
#   * Identical Supabase schema (clients table + increment_request_count
#     RPC). Optional new columns ('plan') are auto-detected if present.
#   * All v1.x endpoints and response shapes preserved.
# 
# REQUIREMENTS (pip):
#   fastapi uvicorn httpx beautifulsoup4 supabase stripe slowapi
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# SECTION 1 - CORE INITIALIZATION
# -----------------------------------------------------------------------------
import os
import re
import hmac
import time
import uuid
import json
import random
import hashlib
import logging
import asyncio
from collections import OrderedDict, defaultdict, deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlunparse, parse_qs

import httpx
from bs4 import BeautifulSoup
from supabase import create_client, Client
from fastapi import (
    FastAPI,
    Request,
    Depends,
    HTTPException,
    Header,
    BackgroundTasks,
    Query,
)
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from pydantic import BaseModel, Field, field_validator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import stripe

# --- Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("titanflow")

# --- Environment (names unchanged from v1.x) ---
SUPABASE_URL: str            = os.environ["SUPABASE_URL"]
SUPABASE_KEY: str            = os.environ["SUPABASE_SERVICE_ROLE_KEY"]
STRIPE_SECRET_KEY: str       = os.environ["STRIPE_SECRET_KEY"]
STRIPE_WEBHOOK_SECRET: str   = os.environ["STRIPE_WEBHOOK_SECRET"]
STRIPE_PRO_PRICE_ID: str     = os.environ.get("STRIPE_PRO_PRICE_ID", "")
STRIPE_CHECKOUT_URL: str     = os.environ.get("STRIPE_CHECKOUT_URL", "https://buy.stripe.com/titanflow-pro")

ADMIN_SECRET: str            = os.environ.get("ADMIN_SECRET", "")

# Optional knobs - all have safe defaults, no env changes required
SCRAPER_PROXY_URL: str = os.environ.get("SCRAPER_PROXY_URL", "")
CACHE_TTL_SECONDS: int = int(os.environ.get("CACHE_TTL_SECONDS", "300"))
CACHE_MAX_ENTRIES: int = int(os.environ.get("CACHE_MAX_ENTRIES", "5000"))
SCRAPE_TIMEOUT: int    = int(os.environ.get("SCRAPE_TIMEOUT", "15"))
BATCH_CONCURRENCY: int = int(os.environ.get("BATCH_CONCURRENCY", "5"))

SERVICE_VERSION = "2.0.0"
STARTED_AT      = datetime.now(timezone.utc)

# --- Plan matrix (multi-tier) --------------------------------
#   monthly_quota = None -> unlimited
PLANS: Dict[str, Dict[str, Any]] = {
    "free": {
        "monthly_quota": 1_000,
        "rate_limit":    "60/minute",
        "batch_max_urls": 5,
        "label":         "Free",
    },
    "pro": {
        "monthly_quota": None,
                "rate_limit":    "300/minute",
        "batch_max_urls": 50,
        "label":         "Pro",
    },
    "enterprise": {
        "monthly_quota": None,
        "rate_limit":    "1200/minute",
        "batch_max_urls": 250,
        "label":         "Enterprise",
    }
}

# --- TTL + LRU In-Memory Cache Engine ---
class LRUCache:
    def __init__(self, maxsize: int, ttl_seconds: int):
        self.maxsize = maxsize
        self.ttl = ttl_seconds
        self.cache = OrderedDict()
        self.lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[Any]:
        async with self.lock:
            if key not in self.cache:
                return None
            val, expires_at = self.cache[key]
            if time.time() > expires_at:
                del self.cache[key]
                return None
            self.cache.move_to_end(key)
            return val

    async def set(self, key: str, value: Any) -> None:
        async with self.lock:
            if key in self.cache:
                del self.cache[key]
            elif len(self.cache) >= self.maxsize:
                self.cache.popitem(last=False)
            expires_at = time.time() + self.ttl
            self.cache[key] = (value, expires_at)

    async def clear(self) -> None:
        async with self.lock:
            self.cache.clear()

RESPONSE_CACHE = LRUCache(maxsize=CACHE_MAX_ENTRIES, ttl_seconds=CACHE_TTL_SECONDS)

# --- Background Job Store (Multi-tenant) ---
class BatchJobStore:
    def __init__(self):
        self.jobs = {}
        self.lock = asyncio.Lock()

    async def create_job(self, client_id: str, total_urls: int) -> str:
        job_id = str(uuid.uuid4())
        async with self.lock:
            self.jobs[job_id] = {
                "job_id": job_id,
                "client_id": client_id,
                "status": "pending",
                "total_urls": total_urls,
                "processed_urls": 0,
                "results": [],
                "created_at": datetime.now(timezone.utc).isoformat(),
                "completed_at": None
            }
        return job_id

    async def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        async with self.lock:
            return self.jobs.get(job_id)

    async def update_job_progress(self, job_id: str, result: Dict[str, Any]) -> None:
        async with self.lock:
            if job_id in self.jobs:
                job = self.jobs[job_id]
                job["results"].append(result)
                job["processed_urls"] += 1
                if job["processed_urls"] >= job["total_urls"]:
                    job["status"] = "completed"
                    job["completed_at"] = datetime.now(timezone.utc).isoformat()

BATCH_JOB_STORE = BatchJobStore()

# --- Anti-Bot & Fingerprint Evasion Matrix ---
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3.1 Mobile/15E148 Safari/605.1.15"
]

CLIENT_HINTS = [
    {"sec-ch-ua": '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"', "sec-ch-ua-mobile": "?0", "sec-ch-ua-platform": '"Windows"'},
    {"sec-ch-ua": '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"', "sec-ch-ua-mobile": "?0", "sec-ch-ua-platform": '"macOS"'},
    {"sec-ch-ua": '"Firefox";v="123"', "sec-ch-ua-mobile": "?0", "sec-ch-ua-platform": '"Linux"'}
]

ACCEPT_LANGUAGES = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.8,en;q=0.7",
    "en-US,en;q=0.5"
]

def get_random_headers(host: str) -> Dict[str, str]:
    ua = random.choice(USER_AGENTS)
    headers = {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": random.choice(ACCEPT_LANGUAGES),
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Host": host
    }
    if "Chrome" in ua:
        hint = random.choice(CLIENT_HINTS)
        headers.update(hint)
    return headers

# --- Domain-Level Circuit Breakers ---
class CircuitBreaker:
    def __init__(self, failure_threshold: int = 5, recovery_time: int = 30):
        self.threshold = failure_threshold
        self.recovery_time = recovery_time
        self.failure_counts = defaultdict(int)
        self.last_failure_time = defaultdict(float)
        self.state = defaultdict(lambda: "CLOSED") # CLOSED, OPEN, HALF-OPEN
        self.lock = asyncio.Lock()

    async def can_request(self, domain: str) -> bool:
        async with self.lock:
            if self.state[domain] == "OPEN":
                if time.time() - self.last_failure_time[domain] > self.recovery_time:
                    self.state[domain] = "HALF-OPEN"
                    return True
                return False
            return True

    async def record_failure(self, domain: str) -> None:
        async with self.lock:
            self.failure_counts[domain] += 1
            self.last_failure_time[domain] = time.time()
            if self.failure_counts[domain] >= self.threshold:
                self.state[domain] = "OPEN"
                logger.error(f"Circuit breaker OPENED for domain: {domain}")

    async def record_success(self, domain: str) -> None:
        async with self.lock:
            self.failure_counts[domain] = 0
            self.state[domain] = "CLOSED"

CIRCUIT_BREAKER = CircuitBreaker()

# -----------------------------------------------------------------------------
# SECTION 2 - PLATFORM CANONICALIZATION & MATCHING
# -----------------------------------------------------------------------------

AMAZON_DOMAINS = {
    "amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.it", "amazon.es",
    "amazon.ca", "amazon.com.mx", "amazon.com.br", "amazon.com.au", "amazon.in",
    "amazon.co.jp", "amazon.cn", "amazon.sa", "amazon.ae", "amazon.sg", "amazon.tr",
    "amazon.nl", "amazon.se", "amazon.pl", "amazon.eg", "amazon.co.za", "amazon.ng",
    "amazon.com.be", "amazon.com.cl", "amazon.com.co", "amazon.com.ng", "amazon.com.sa"
}

AMAZON_SHORT_DOMAINS = {
    "amzn.to", "amzn.eu", "amzn.asia", "amzn.gallery", "amzn.in", "amzn.space", 
    "amzn.link", "amzn.live", "amzn.blog", "amzn.shop", "amzn.store", "amzn.market", 
    "amzn.deals", "amzn.app", "amzn.click", "amzn.page", "amzn.press", "amzn.zone"
}

def clean_url(url: str) -> str:
    try:
        parsed = urlparse(url.strip())
        scheme = parsed.scheme if parsed.scheme else "https"
        netloc = parsed.netloc.lower()
        if netloc.startswith("www."):
            netloc = netloc[4:]
        return urlunparse((scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))
    except Exception:
        return url

def identify_platform(url: str) -> Tuple[str, str]:
    """
    Returns (platform_id, canonical_url or extracted_id)
    Supported: amazon, flipkart, meesho, ebay, walmart, aliexpress, myntra, ajio
    """
    cleaned = clean_url(url)
    try:
        parsed = urlparse(cleaned)
        domain = parsed.netloc
        path = parsed.path

        # Amazon shortlinks conversion hint (will resolve fully via HTTPX in engine)
        if domain in AMAZON_SHORT_DOMAINS:
            return "amazon", cleaned

        if domain in AMAZON_DOMAINS:
            # Extract ASIN
            asin_match = re.search(r"/(?:dp|gp/product|exec/obidos/asin)/([A-Z0-9]{10})", path, re.IGNORECASE)
            if asin_match:
                asin = asin_match.group(1)
                # Keep affiliate tag if present
                qs = parse_qs(parsed.query)
                tag = qs.get("tag", [None])[0]
                canonical = f"https://{domain}/dp/{asin}"
                if tag:
                    canonical += f"?tag={tag}"
                return "amazon", canonical
            return "amazon", cleaned

        if "flipkart.com" in domain:
            # Keep pid (Product ID) for canonicalization
            qs = parse_qs(parsed.query)
            pid = qs.get("pid", [None])[0]
            if pid:
                # Strip extra marketing query parameters
                return "flipkart", f"https://www.flipkart.com{path}?pid={pid}"
            return "flipkart", cleaned

        if "meesho.com" in domain:
            return "meesho", cleaned

        if "ebay.com" in domain or any(x in domain for x in [".ebay.co.uk", ".ebay.de", ".ebay.com.au"]):
            # Extract item ID if possible
            item_match = re.search(r"/itm/(?:[^/]+/)?(\d+)", path)
            if item_match:
                return "ebay", f"https://www.ebay.com/itm/{item_match.group(1)}"
            return "ebay", cleaned

        if "walmart.com" in domain:
            return "walmart", cleaned

        if "aliexpress.com" in domain or "aliexpress.ru" in domain:
            item_match = re.search(r"/item/(\d+)\.html", path)
            if item_match:
                return "aliexpress", f"https://www.aliexpress.com/item/{item_match.group(1)}.html"
            return "aliexpress", cleaned

        if "myntra.com" in domain:
            return "myntra", cleaned

        if "ajio.com" in domain:
            return "ajio", cleaned

    except Exception:
        pass
    return "unknown", url

# -----------------------------------------------------------------------------
# SECTION 3 - DEEP EXTRACTION ENGINES (BeautifulSoup4 + JSON-LD Engine)
# -----------------------------------------------------------------------------

def extract_json_ld(soup: BeautifulSoup) -> List[Dict[str, Any]]:
    results = []
    scripts = soup.find_all("script", type="application/ld+json")
    for script in scripts:
        try:
            if script.string:
                data = json.loads(script.string.strip())
                if isinstance(data, list):
                    results.extend(data)
                else:
                    results.append(data)
        except Exception:
            continue
    return results
            
