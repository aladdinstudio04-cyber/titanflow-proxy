# ══════════════════════════════════════════════════════════════════════════════
#  TitanFlow Data API  —  main.py
#  Enterprise-grade · Multi-tenant · SaaS-ready · Global Commerce Scale
#  Author: TitanFlow Engineering
#  Version: 2.0.0
#
#  v2.0.0 — "Atlas" Release  (major upgrade)
#  ──────────────────────────────────────────────────────────────────────────────
#  SCRAPING POWER
#    • Anti-bot evasion: rotating browser fingerprints (UA + client
#      hints + Accept-Language pools), per-attempt header rotation
#    • Bot-challenge / CAPTCHA detection with automatic identity
#      rotation and retry
#    • Smart retries: jittered exponential backoff, Retry-After
#      honoring on 429/503, per-domain circuit breaker
#    • Optional upstream proxy support (SCRAPER_PROXY_URL)
#    • Connection pooling via a shared HTTP/2-capable client
#    • Deep extraction: JSON-LD (schema.org) engine + per-platform CSS
#      engines → brand, seller, features, breadcrumbs, image galleries,
#      ratings, review counts, stock, discounts, currency detection
#
#  PLATFORM COVERAGE  (8 platforms, 40+ domains)
#    • Amazon (all 20 storefronts + 10 shortlink domains, ASIN
#      canonicalization, affiliate-tag preservation)
#    • Flipkart · Meesho · eBay (global storefronts) · Walmart
#    • AliExpress · Myntra · Ajio
#
#  ENTERPRISE INFRASTRUCTURE
#    • In-process TTL+LRU response cache (per-URL, bypass via fresh=true)
#    • Async batch job queue: POST /v1/batch → job id → poll results
#    • Usage analytics per client: platform mix, latency, cache ratio
#    • Multi-tier plans: FREE / PRO / ENTERPRISE (quota, rate, batch size)
#    • Idempotent Stripe webhooks (event-id dedup store)
#    • Request-ID tracing, process-time headers, GZip compression
#    • /metrics operational endpoint, hardened /health probe
#
#  SECURITY HARDENING
#    • Constant-time API-key & admin-secret comparison (hmac.compare_digest)
#    • API keys never logged (masked suffix only)
#    • Stripe signatures verified on the raw body (official SDK)
#    • Per-API-key rate limiting (falls back to client IP)
#
#  BACKWARD COMPATIBILITY
#    • Identical env var names: SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY,
#      STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET, STRIPE_PRO_PRICE_ID,
#      STRIPE_CHECKOUT_URL, ADMIN_SECRET
#    • Identical Supabase schema (clients table + increment_request_count
#      RPC). Optional new columns (`plan`) are auto-detected if present.
#    • All v1.x endpoints and response shapes preserved.
#
#  REQUIREMENTS (pip):
#    fastapi  uvicorn  httpx  beautifulsoup4  supabase  stripe  slowapi
# ══════════════════════════════════════════════════════════════════════════════

# ──────────────────────────────────────────────────────────────────────────────
#  SECTION 1 — CORE INITIALIZATION
# ──────────────────────────────────────────────────────────────────────────────

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

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("titanflow")

# ── Environment (names unchanged from v1.x) ──────────────────
SUPABASE_URL: str          = os.environ["SUPABASE_URL"]
SUPABASE_KEY: str          = os.environ["SUPABASE_SERVICE_ROLE_KEY"]
STRIPE_SECRET_KEY: str     = os.environ["STRIPE_SECRET_KEY"]
STRIPE_WEBHOOK_SECRET: str = os.environ["STRIPE_WEBHOOK_SECRET"]
STRIPE_PRO_PRICE_ID: str   = os.environ.get("STRIPE_PRO_PRICE_ID", "")
STRIPE_CHECKOUT_URL: str   = os.environ.get("STRIPE_CHECKOUT_URL", "https://buy.stripe.com/titanflow-pro")
ADMIN_SECRET: str          = os.environ.get("ADMIN_SECRET", "")

# Optional knobs — all have safe defaults, no env changes required
SCRAPER_PROXY_URL: str  = os.environ.get("SCRAPER_PROXY_URL", "")
CACHE_TTL_SECONDS: int  = int(os.environ.get("CACHE_TTL_SECONDS", "300"))
CACHE_MAX_ENTRIES: int  = int(os.environ.get("CACHE_MAX_ENTRIES", "5000"))
SCRAPE_TIMEOUT: int     = int(os.environ.get("SCRAPE_TIMEOUT", "15"))
BATCH_CONCURRENCY: int  = int(os.environ.get("BATCH_CONCURRENCY", "5"))

SERVICE_VERSION = "2.0.0"
STARTED_AT      = datetime.now(timezone.utc)

# ── Plan matrix (multi-tier) ──────────────────────────────────
#   monthly_quota = None → unlimited
PLANS: Dict[str, Dict[str, Any]] = {
    "free": {
        "monthly_quota":  1_000,
        "rate_limit":     "60/minute",
        "batch_max_urls": 5,
        "label":          "Free",
    },
    "pro": {
        "monthly_quota":  None,
        "rate_limit":     "300/minute",
        "batch_max_urls": 25,
        "label":          "Pro",
    },
    "enterprise": {
        "monthly_quota":  None,
        "rate_limit":     "1000/minute",
        "batch_max_urls": 100,
        "label":          "Enterprise",
    },
}
FREE_TIER_LIMIT: int = PLANS["free"]["monthly_quota"]  # kept for v1.x compat

# ── Clients ───────────────────────────────────────────────────
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
stripe.api_key   = STRIPE_SECRET_KEY

# ── Rate-limiter (keyed by API key, IP fallback) ─────────────
def _rate_limit_key(request: Request) -> str:
    api_key = request.headers.get("X-Api-Key")
    if api_key:
        return hashlib.sha256(api_key.encode()).hexdigest()[:24]
    return get_remote_address(request)


limiter = Limiter(key_func=_rate_limit_key, default_limits=["200/minute"])


# ──────────────────────────────────────────────────────────────────────────────
#  SECTION 2 — OBSERVABILITY  (metrics · tracing · middleware)
# ──────────────────────────────────────────────────────────────────────────────

class MetricsRegistry:
    """Lock-free in-process counters (single event loop → safe)."""

    def __init__(self) -> None:
        self.requests_total: int   = 0
        self.scrapes_ok: int       = 0
        self.scrapes_failed: int   = 0
        self.cache_hits: int       = 0
        self.cache_misses: int     = 0
        self.bot_challenges: int   = 0
        self.circuit_rejections: int = 0
        self.webhook_events: int   = 0
        self.webhook_duplicates: int = 0
        self.batch_jobs_created: int = 0
        self.platform_counts: Dict[str, int] = defaultdict(int)
        self.latency_sum_ms: float = 0.0
        self.latency_samples: int  = 0

    def observe_latency(self, ms: float) -> None:
        self.latency_sum_ms += ms
        self.latency_samples += 1

    @property
    def avg_latency_ms(self) -> float:
        if not self.latency_samples:
            return 0.0
        return round(self.latency_sum_ms / self.latency_samples, 1)

    def snapshot(self) -> Dict[str, Any]:
        uptime = (datetime.now(timezone.utc) - STARTED_AT).total_seconds()
        total_cache = self.cache_hits + self.cache_misses
        return {
            "uptime_seconds":     round(uptime),
            "requests_total":     self.requests_total,
            "scrapes_ok":         self.scrapes_ok,
            "scrapes_failed":     self.scrapes_failed,
            "avg_scrape_latency_ms": self.avg_latency_ms,
            "cache": {
                "hits":      self.cache_hits,
                "misses":    self.cache_misses,
                "hit_ratio": round(self.cache_hits / total_cache, 3) if total_cache else 0.0,
            },
            "bot_challenges_detected": self.bot_challenges,
            "circuit_breaker_rejections": self.circuit_rejections,
            "stripe_webhooks": {
                "processed":  self.webhook_events,
                "duplicates": self.webhook_duplicates,
            },
            "batch_jobs_created": self.batch_jobs_created,
            "platform_breakdown": dict(self.platform_counts),
        }


METRICS = MetricsRegistry()


def _mask_key(key: str) -> str:
    """Never log a full API key — suffix only."""
    return f"…{key[-6:]}" if key and len(key) >= 6 else "…?"


# ──────────────────────────────────────────────────────────────────────────────
#  SECTION 3 — RESILIENCE PRIMITIVES  (cache · circuit breaker)
# ──────────────────────────────────────────────────────────────────────────────

class TTLCache:
    """In-process TTL + LRU cache. Single-event-loop safe."""

    def __init__(self, max_entries: int, ttl_seconds: int) -> None:
        self._store: "OrderedDict[str, Tuple[float, Any]]" = OrderedDict()
        self._max = max_entries
        self._ttl = ttl_seconds

    def get(self, key: str) -> Optional[Any]:
        item = self._store.get(key)
        if item is None:
            return None
        expires_at, value = item
        if time.monotonic() > expires_at:
            self._store.pop(key, None)
            return None
        self._store.move_to_end(key)
        return value

    def set(self, key: str, value: Any) -> None:
        if key in self._store:
            self._store.move_to_end(key)
        self._store[key] = (time.monotonic() + self._ttl, value)
        while len(self._store) > self._max:
            self._store.popitem(last=False)

    def purge(self) -> int:
        n = len(self._store)
        self._store.clear()
        return n

    def __len__(self) -> int:
        return len(self._store)


SCRAPE_CACHE = TTLCache(max_entries=CACHE_MAX_ENTRIES, ttl_seconds=CACHE_TTL_SECONDS)


class CircuitBreaker:
    """
    Per-domain circuit breaker.
    Opens after `threshold` failures inside `window` seconds; rejects
    traffic for `cooldown` seconds, then half-opens automatically.
    """

    def __init__(self, threshold: int = 5, window: float = 60.0, cooldown: float = 30.0) -> None:
        self._failures: Dict[str, deque] = defaultdict(deque)
        self._open_until: Dict[str, float] = {}
        self._threshold = threshold
        self._window = window
        self._cooldown = cooldown

    def is_open(self, domain: str) -> bool:
        until = self._open_until.get(domain, 0.0)
        if time.monotonic() < until:
            return True
        if domain in self._open_until:
            # cooldown elapsed → half-open (allow traffic again)
            self._open_until.pop(domain, None)
            self._failures[domain].clear()
        return False

    def record_failure(self, domain: str) -> None:
        now = time.monotonic()
        q = self._failures[domain]
        q.append(now)
        while q and now - q[0] > self._window:
            q.popleft()
        if len(q) >= self._threshold:
            self._open_until[domain] = now + self._cooldown
            logger.warning("Circuit OPEN for domain=%s (cooldown %ss)", domain, self._cooldown)

    def record_success(self, domain: str) -> None:
        self._failures[domain].clear()
        self._open_until.pop(domain, None)

    def open_domains(self) -> List[str]:
        now = time.monotonic()
        return [d for d, t in self._open_until.items() if t > now]


BREAKER = CircuitBreaker()


class IdempotencyStore:
    """Bounded set of processed Stripe event IDs (LRU eviction)."""

    def __init__(self, max_entries: int = 10_000) -> None:
        self._seen: "OrderedDict[str, float]" = OrderedDict()
        self._max = max_entries

    def seen_before(self, event_id: str) -> bool:
        if event_id in self._seen:
            self._seen.move_to_end(event_id)
            return True
        self._seen[event_id] = time.monotonic()
        while len(self._seen) > self._max:
            self._seen.popitem(last=False)
        return False


STRIPE_EVENTS = IdempotencyStore()


# ──────────────────────────────────────────────────────────────────────────────
#  SECTION 4 — APP FACTORY  (lifespan · middleware)
# ──────────────────────────────────────────────────────────────────────────────

_http_client: Optional[httpx.AsyncClient] = None


def get_http_client() -> httpx.AsyncClient:
    """Shared pooled HTTP client (created lazily / at startup)."""
    global _http_client
    if _http_client is None or _http_client.is_closed:
        kwargs: Dict[str, Any] = {
            "follow_redirects": True,
            "timeout": httpx.Timeout(SCRAPE_TIMEOUT),
            "limits": httpx.Limits(max_connections=50, max_keepalive_connections=20),
        }
        if SCRAPER_PROXY_URL:
            kwargs["proxy"] = SCRAPER_PROXY_URL
        _http_client = httpx.AsyncClient(**kwargs)
    return _http_client


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("TitanFlow Data API v%s — starting up.", SERVICE_VERSION)
    get_http_client()
    try:
        supabase.table("clients").select("id").limit(1).execute()
        logger.info("Supabase connection: OK")
    except Exception as exc:
        logger.critical("Supabase connection FAILED at startup: %s", exc)
    if SCRAPER_PROXY_URL:
        logger.info("Upstream scraper proxy: ENABLED")
    yield
    if _http_client and not _http_client.is_closed:
        await _http_client.aclose()
    logger.info("TitanFlow Data API — shut down gracefully.")


app = FastAPI(
    title="TitanFlow Data API",
    description=(
        "Real-time product intelligence for modern commerce teams. "
        "Supports Amazon (all storefronts + shortlinks), Flipkart, Meesho, "
        "eBay, Walmart, AliExpress, Myntra, and Ajio. "
        "Built-in caching, batch jobs, usage analytics, and multi-tier plans."
    ),
    version=SERVICE_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(GZipMiddleware, minimum_size=1024)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def observability_middleware(request: Request, call_next: Callable[[Request], Awaitable]):
    """Request-ID tracing + process time + global request counter."""
    request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex[:16]
