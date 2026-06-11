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
    request.state.request_id = request_id
    METRICS.requests_total += 1
    start = time.monotonic()
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Process-Time-Ms"] = str(round((time.monotonic() - start) * 1000))
    return response


# ──────────────────────────────────────────────────────────────────────────────
#  SECTION 5 — DATABASE SECURITY LAYER
# ──────────────────────────────────────────────────────────────────────────────

class AuthenticatedClient(BaseModel):
    """Validated client attached to every protected request."""
    id:                  str
    email:               str
    api_key:             str
    is_pro:              bool
    requests_this_month: int
    plan:                str = "free"

    class Config:
        frozen = True

    @property
    def plan_config(self) -> Dict[str, Any]:
        return PLANS.get(self.plan, PLANS["free"])


def _resolve_plan(row: Dict[str, Any]) -> str:
    """
    Plan resolution with full backward compatibility:
      1. Explicit `plan` column if present and valid (new schema, optional)
      2. Legacy `is_pro` boolean → pro / free
    """
    explicit = (row.get("plan") or "").strip().lower()
    if explicit in PLANS:
        return explicit
    return "pro" if row.get("is_pro") else "free"


async def verify_api_key(x_api_key: str = Header(...)) -> AuthenticatedClient:
    """
    Dependency injected on every protected endpoint.

    1. Validates API key against Supabase `clients` table.
    2. Constant-time key comparison (timing-attack defense in depth).
    3. Enforces plan quota (free: 1 000 req/month; pro/enterprise: unlimited).
    4. Increments request counter atomically via RPC (best-effort).
    """
    if not x_api_key or len(x_api_key) < 32:
        raise HTTPException(
            status_code=401,
            detail={"error": "INVALID_API_KEY", "message": "Provide a valid X-Api-Key header."},
        )

    try:
        result = (
            supabase.table("clients")
            .select("*")
            .eq("api_key", x_api_key)
            .limit(1)
            .execute()
        )
    except Exception as exc:
        logger.error("Supabase lookup failed for key %s: %s", _mask_key(x_api_key), exc)
        raise HTTPException(
            status_code=503,
            detail={"error": "DB_UNAVAILABLE", "message": "Database unreachable. Retry shortly."},
        )

    rows = result.data or []
    client_row = rows[0] if rows else None
    if not client_row:
        raise HTTPException(
            status_code=401,
            detail={"error": "UNAUTHORIZED", "message": "API key not found."},
        )

    # Constant-time comparison — defense in depth over the DB equality match
    if not hmac.compare_digest(str(client_row.get("api_key", "")), x_api_key):
        raise HTTPException(
            status_code=401,
            detail={"error": "UNAUTHORIZED", "message": "API key not found."},
        )

    client = AuthenticatedClient(
        id=str(client_row["id"]),
        email=client_row["email"],
        api_key=client_row["api_key"],
        is_pro=bool(client_row.get("is_pro", False)),
        requests_this_month=int(client_row.get("requests_this_month", 0)),
        plan=_resolve_plan(client_row),
    )

    # ── Quota check (plan-aware) ──────────────────────────────
    quota = client.plan_config["monthly_quota"]
    if quota is not None and client.requests_this_month >= quota:
        raise HTTPException(
            status_code=402,
            detail={
                "error":         "QUOTA_EXCEEDED",
                "message":       f"{client.plan_config['label']} tier limit of {quota} requests/month reached.",
                "upgrade_url":   STRIPE_CHECKOUT_URL,
                "current_usage": client.requests_this_month,
                "limit":         quota,
            },
        )

    # ── Atomic increment (best-effort, never blocks the user) ─
    try:
        supabase.rpc("increment_request_count", {"client_id": client.id}).execute()
    except Exception as exc:
        logger.warning("Counter increment failed for %s: %s", client.id, exc)

    return client


# ──────────────────────────────────────────────────────────────────────────────
#  SECTION 6 — ANTI-BOT HTTP ENGINE
#  Rotating fingerprints · jittered retries · Retry-After honoring ·
#  bot-challenge detection · per-domain circuit breaker
# ──────────────────────────────────────────────────────────────────────────────

class BotChallengeDetected(Exception):
    """Raised when the target serves a CAPTCHA / bot interstitial."""


class CircuitOpen(Exception):
    """Raised when a target domain's circuit breaker is open."""


# Realistic browser identities, rotated per attempt.
_BROWSER_IDENTITIES: List[Dict[str, str]] = [
    {  # Chrome 124 / Windows
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        ),
        "Sec-Ch-Ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
    },
    {  # Chrome 123 / macOS
        "User-Agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
        ),
        "Sec-Ch-Ua": '"Chromium";v="123", "Google Chrome";v="123", "Not-A.Brand";v="99"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"macOS"',
    },
    {  # Firefox 125 / Windows
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) "
            "Gecko/20100101 Firefox/125.0"
        ),
    },
    {  # Firefox 124 / Linux
        "User-Agent": (
            "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0"
        ),
    },
    {  # Safari 17 / macOS
        "User-Agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
            "(KHTML, like Gecko) Version/17.4 Safari/605.1.15"
        ),
    },
    {  # Edge 124 / Windows
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0"
        ),
        "Sec-Ch-Ua": '"Chromium";v="124", "Microsoft Edge";v="124", "Not-A.Brand";v="99"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
    },
    {  # Chrome 122 / Android (mobile pages sometimes evade desktop blocks)
        "User-Agent": (
            "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36"
        ),
        "Sec-Ch-Ua-Mobile": "?1",
        "Sec-Ch-Ua-Platform": '"Android"',
    },
]

_ACCEPT_LANGUAGES: List[str] = [
    "en-US,en;q=0.9",
    "en-IN,en;q=0.9,hi;q=0.7",
    "en-GB,en;q=0.9",
    "en-US,en;q=0.8,es;q=0.5",
]

# Signatures of bot-challenge / CAPTCHA interstitials
_BOT_SIGNATURES: List[str] = [
    "api-services-support@amazon.com",
    "enter the characters you see below",
    "to discuss automated access to amazon data",
    "robot check",
    "/errors/validatecaptcha",
    "px-captcha",
    "are you a human",
    "verify you are a human",
    "access denied | www.walmart.com",
    "captcha-delivery.com",
    "punish?x5secdata",          # AliExpress sec gateway
]


def build_scrape_headers() -> Dict[str, str]:
    """Compose a realistic, randomized browser fingerprint."""
    identity = random.choice(_BROWSER_IDENTITIES)
    headers: Dict[str, str] = {
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,*/*;q=0.8"
        ),
        "Accept-Language": random.choice(_ACCEPT_LANGUAGES),
        "Accept-Encoding": "gzip, deflate, br",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "DNT": "1",
    }
    headers.update(identity)
    return headers


# Legacy alias preserved for v1.x internal compat
SCRAPE_HEADERS: Dict[str, str] = build_scrape_headers()


def _looks_like_bot_challenge(html: str) -> bool:
    if not html:
        return False
    lowered = html[:20_000].lower()
    return any(sig in lowered for sig in _BOT_SIGNATURES)


def _retry_after_seconds(response: httpx.Response) -> Optional[float]:
    raw = response.headers.get("Retry-After")
    if not raw:
        return None
    try:
        return min(float(raw), 10.0)  # cap waits — we are an API, not a browser
    except ValueError:
        return None


async def _fetch_html(url: str, client: Optional[httpx.AsyncClient] = None) -> str:
    """
    Hardened async fetch:
      • per-domain circuit breaker
      • 4 attempts with jittered exponential backoff
      • rotates browser identity on every attempt
      • honors Retry-After on 429/503
      • detects bot challenges and retries with a fresh fingerprint
    """
    http = client or get_http_client()
    domain = _domain_of(url)

    if BREAKER.is_open(domain):
        METRICS.circuit_rejections += 1
        raise CircuitOpen(domain)

    last_exc: Optional[Exception] = None
    for attempt in range(1, 5):
        headers = build_scrape_headers()
        try:
            response = await http.get(url, headers=headers, timeout=SCRAPE_TIMEOUT, follow_redirects=True)

            if response.status_code in (429, 503):
                wait = _retry_after_seconds(response) or (2 ** attempt) * random.uniform(0.5, 1.0)
                if attempt == 4:
                    response.raise_for_status()
                await asyncio.sleep(wait)
                continue

            response.raise_for_status()
            html = response.text

            if _looks_like_bot_challenge(html):
                METRICS.bot_challenges += 1
                logger.warning("Bot challenge from %s (attempt %d) — rotating identity.", domain, attempt)
                if attempt == 4:
                    BREAKER.record_failure(domain)
                    raise BotChallengeDetected(domain)
                await asyncio.sleep(attempt * random.uniform(0.8, 1.6))
                continue

            BREAKER.record_success(domain)
            return html

        except httpx.HTTPStatusError as exc:
            last_exc = exc
            if exc.response.status_code in (403, 404, 410):
                if exc.response.status_code == 403:
                    BREAKER.record_failure(domain)
                raise  # no point retrying hard denials / missing pages
            if attempt == 4:
                BREAKER.record_failure(domain)
                raise
            await asyncio.sleep((2 ** attempt) * random.uniform(0.5, 1.0))
        except httpx.RequestError as exc:
            last_exc = exc
            if attempt == 4:
                BREAKER.record_failure(domain)
                raise
            await asyncio.sleep((2 ** attempt) * random.uniform(0.5, 1.0))

    raise last_exc or RuntimeError("fetch failed")  # unreachable safety net


# ──────────────────────────────────────────────────────────────────────────────
#  SECTION 7 — EXTRACTION TOOLKIT
#  shared parsing helpers + schema.org JSON-LD engine
# ──────────────────────────────────────────────────────────────────────────────

def _clean_price(raw: str) -> Optional[float]:
    """Strip currency symbols / separators and return float or None."""
    if not raw:
        return None
    cleaned = re.sub(r"[^\d.]", "", raw.replace(",", ""))
    if cleaned.count(".") > 1:  # e.g. European thousand separators
        cleaned = cleaned.replace(".", "", cleaned.count(".") - 1)
    try:
        return float(cleaned) if cleaned else None
    except ValueError:
        return None


def _parse_int(raw: str) -> Optional[int]:
    if not raw:
        return None
    m = re.search(r"([\d,]+)", raw)
    return int(m.group(1).replace(",", "")) if m else None


def _discount_pct(price: Optional[float], original: Optional[float]) -> Optional[float]:
    if price and original and original > price:
        return round((original - price) / original * 100, 1)
    return None


def _text_or_none(tag) -> Optional[str]:
    return tag.get_text(strip=True) if tag else None


def extract_json_ld_product(soup: BeautifulSoup) -> Dict[str, Any]:
    """
    Universal schema.org Product extractor.
    Most modern commerce sites (eBay, Walmart, Ajio, Flipkart variants)
    embed <script type="application/ld+json"> blocks. This walks every
    block, finds the Product node, and returns normalized fields.
    """
    out: Dict[str, Any] = {}
    for script in soup.find_all("script", type="application/ld+json"):
        try:
            payload = json.loads(script.string or "")
        except (json.JSONDecodeError, TypeError):
            continue

        candidates: List[Dict[str, Any]] = []
        if isinstance(payload, dict):
            if "@graph" in payload and isinstance(payload["@graph"], list):
                candidates.extend(x for x in payload["@graph"] if isinstance(x, dict))
            else:
                candidates.append(payload)
        elif isinstance(payload, list):
            candidates.extend(x for x in payload if isinstance(x, dict))

        for node in candidates:
            node_type = node.get("@type", "")
            types = node_type if isinstance(node_type, list) else [node_type]
            if "Product" not in types:
                continue

            out["title"] = node.get("name") or out.get("title")
            brand = node.get("brand")
            if isinstance(brand, dict):
                out["brand"] = brand.get("name")
            elif isinstance(brand, str):
                out["brand"] = brand

            image = node.get("image")
            if isinstance(image, list) and image:
                out["images"] = [i for i in image if isinstance(i, str)][:8]
                out["image_url"] = out["images"][0] if out.get("images") else None
            elif isinstance(image, str):
                out["image_url"] = image

            rating = node.get("aggregateRating")
            if isinstance(rating, dict):
                try:
                    out["rating"] = float(rating.get("ratingValue"))
                except (TypeError, ValueError):
                    pass
                try:
                    out["review_count"] = int(rating.get("reviewCount") or rating.get("ratingCount"))
                except (TypeError, ValueError):
                    pass

            offers = node.get("offers")
            if isinstance(offers, list) and offers:
                offers = offers[0]
            if isinstance(offers, dict):
                try:
                    out["price"] = float(offers.get("price"))
                except (TypeError, ValueError):
                    low = offers.get("lowPrice")
                    try:
                        out["price"] = float(low)
                    except (TypeError, ValueError):
                        pass
                if offers.get("priceCurrency"):
                    out["currency"] = offers["priceCurrency"]
                availability = str(offers.get("availability", ""))
                if availability:
                    out["in_stock"] = "instock" in availability.lower().replace(" ", "")
                seller = offers.get("seller")
                if isinstance(seller, dict) and seller.get("name"):
                    out["seller"] = seller["name"]

            out["description"] = (node.get("description") or "")[:500] or out.get("description")
            return out  # first Product node wins
    return out


def _meta_content(soup: BeautifulSoup, *prop_names: str) -> Optional[str]:
    """Read OpenGraph / meta tags as a last-resort fallback."""
    for name in prop_names:
        tag = soup.find("meta", attrs={"property": name}) or soup.find("meta", attrs={"name": name})
        if tag and tag.get("content"):
            return tag["content"].strip()
    return None


def _base_result(platform: str, url: str) -> Dict[str, Any]:
    return {
        "platform":   platform,
        "url":        url,
        "scraped_at": datetime.now(timezone.utc).isoformat(),
    }


# ──────────────────────────────────────────────────────────────────────────────
#  SECTION 8 — PLATFORM DOMAIN REGISTRY
# ──────────────────────────────────────────────────────────────────────────────

# Every known Amazon shortlink / redirect domain
AMAZON_SHORTLINK_DOMAINS: frozenset = frozenset([
    "amzn.to", "amzn.in", "amzn.eu", "amzn.com", "amzn.asia",
    "a.co", "z.cn", "amzn.me", "amzn.co.uk", "amzn.co.jp",
])

# Full Amazon retail domains (all 20+ regional storefronts)
AMAZON_RETAIL_DOMAINS: frozenset = frozenset([
    "amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.it",
    "amazon.es", "amazon.co.jp", "amazon.in", "amazon.ca", "amazon.com.au",
    "amazon.com.br", "amazon.com.mx", "amazon.nl", "amazon.se", "amazon.pl",
    "amazon.sg", "amazon.ae", "amazon.sa", "amazon.eg", "amazon.com.tr",
    "amazon.cn", "amazon.com.be", "amazon.ie",
])

# Currency by Amazon storefront (auto-detection)
AMAZON_CURRENCY_MAP: Dict[str, str] = {
    "amazon.com": "USD", "amazon.co.uk": "GBP", "amazon.de": "EUR",
    "amazon.fr": "EUR", "amazon.it": "EUR", "amazon.es": "EUR",
    "amazon.nl": "EUR", "amazon.com.be": "EUR", "amazon.ie": "EUR",
    "amazon.co.jp": "JPY", "amazon.in": "INR", "amazon.ca": "CAD",
    "amazon.com.au": "AUD", "amazon.com.br": "BRL", "amazon.com.mx": "MXN",
    "amazon.se": "SEK", "amazon.pl": "PLN", "amazon.sg": "SGD",
    "amazon.ae": "AED", "amazon.sa": "SAR", "amazon.eg": "EGP",
    "amazon.com.tr": "TRY", "amazon.cn": "CNY",
}

EBAY_DOMAINS: frozenset = frozenset([
    "ebay.com", "ebay.co.uk", "ebay.de", "ebay.fr", "ebay.it", "ebay.es",
    "ebay.ca", "ebay.com.au", "ebay.in", "ebay.nl", "ebay.ie", "ebay.at",
    "ebay.ch", "ebay.pl", "ebay.com.sg", "ebay.com.my", "ebay.ph",
])

EBAY_CURRENCY_MAP: Dict[str, str] = {
    "ebay.com": "USD", "ebay.co.uk": "GBP", "ebay.de": "EUR", "ebay.fr": "EUR",
    "ebay.it": "EUR", "ebay.es": "EUR", "ebay.ca": "CAD", "ebay.com.au": "AUD",
    "ebay.in": "INR", "ebay.nl": "EUR", "ebay.ie": "EUR", "ebay.at": "EUR",
    "ebay.ch": "CHF", "ebay.pl": "PLN", "ebay.com.sg": "SGD",
}

ALIEXPRESS_DOMAINS: frozenset = frozenset([
    "aliexpress.com", "aliexpress.us", "aliexpress.ru", "a.aliexpress.com",
])

WALMART_DOMAINS: frozenset = frozenset(["walmart.com", "walmart.ca"])
MYNTRA_DOMAINS: frozenset  = frozenset(["myntra.com"])
AJIO_DOMAINS: frozenset    = frozenset(["ajio.com"])

# Query-string params that are safe to strip (tracking noise)
_STRIP_PARAMS: frozenset = frozenset([
    "ref", "ref_", "pf_rd_p", "pf_rd_r", "pf_rd_s", "pf_rd_t",
    "pf_rd_i", "pf_rd_m", "pd_rd_wg", "pd_rd_w", "pd_rd_r",
    "pd_rd_i", "dchild", "sprefix", "keywords", "crid", "qid",
    "sr", "s", "field-keywords", "linkId", "linkCode", "camp",
    "creative", "creativeASIN", "adId", "smid", "spLa",
    "cv_ct_cx", "maas", "utm_source", "utm_medium", "utm_campaign",
    "utm_term", "utm_content", "gclid", "fbclid", "mc_id", "wmlspartner",
])


def _domain_of(url: str) -> str:
    """Return bare domain (no www.) from a URL string."""
    try:
        netloc = urlparse(url).netloc.lower()
        return netloc[4:] if netloc.startswith("www.") else netloc
    except Exception:
        return ""


def _domain_matches(domain: str, candidates: frozenset) -> bool:
    return any(domain == c or domain.endswith("." + c) for c in candidates)


def _is_amazon_shortlink(url: str) -> bool:
    return _domain_matches(_domain_of(url), AMAZON_SHORTLINK_DOMAINS)


def _is_amazon_retail(url: str) -> bool:
    return _domain_matches(_domain_of(url), AMAZON_RETAIL_DOMAINS)


def _currency_for_domain(domain: str, mapping: Dict[str, str], default: str) -> str:
    for d, cur in mapping.items():
        if domain == d or domain.endswith("." + d):
            return cur
    return default


# ──────────────────────────────────────────────────────────────────────────────
#  SECTION 9 — DATA EXTRACTION ENGINES  (8 platforms)
# ──────────────────────────────────────────────────────────────────────────────

async def scrape_amazon(url: str) -> Dict[str, Any]:
    """
    Deep extraction from any Amazon storefront:
    title, brand, price + list price + discount, currency (per storefront),
    availability, rating, review count, ASIN, seller, feature bullets,
    breadcrumbs, image gallery.
    """
    html = await _fetch_html(url)
    soup = BeautifulSoup(html, "html.parser")
    domain = _domain_of(url)

    # ── Title / brand ────────────────────────────────────────
    title = _text_or_none(soup.find("span", id="productTitle") or soup.find("h1", id="title"))
    brand = None
    byline = soup.find("a", id="bylineInfo")
    if byline:
        brand = re.sub(r"^(Visit the|Brand:)\s*", "", byline.get_text(strip=True)).replace(" Store", "").strip() or None

    # ── Price (multi-strategy) ────────────────────────────────
    price: Optional[float] = None
    price_whole = soup.find("span", class_="a-price-whole")
    if price_whole:
        raw = price_whole.get_text(strip=True)
        frac = soup.find("span", class_="a-price-fraction")
        if frac:
            raw += frac.get_text(strip=True)
        price = _clean_price(raw)
    if price is None:
        offscreen = soup.select_one("span.a-price span.a-offscreen") or soup.find("span", class_="a-offscreen")
        if offscreen:
            price = _clean_price(offscreen.get_text(strip=True))

    # ── List price / deal discount ────────────────────────────
    list_price: Optional[float] = None
    basis = soup.select_one("span.basisPrice span.a-offscreen") or soup.select_one("span.a-price.a-text-price span.a-offscreen")
    if basis:
        list_price = _clean_price(basis.get_text(strip=True))

    # ── Availability ──────────────────────────────────────────
    avail_text = _text_or_none(soup.find("div", id="availability")) or ""
    in_stock = bool(re.search(r"in stock", avail_text, re.IGNORECASE)) if avail_text else price is not None

    # ── Rating / reviews ──────────────────────────────────────
    rating: Optional[float] = None
    rating_tag = soup.find("span", class_="a-icon-alt")
    if rating_tag:
        m = re.search(r"([\d.]+)\s*(?:out|von|sur|su|de|颗)", rating_tag.get_text())
        if m:
            rating = float(m.group(1))
    review_count = _parse_int(_text_or_none(soup.find("span", id="acrCustomerReviewText")) or "")

    # ── ASIN ──────────────────────────────────────────────────
    asin_tag = soup.find("input", id="ASIN")
    asin = asin_tag.get("value") if asin_tag else _extract_asin_from_url(url)

    # ── Seller / merchant ─────────────────────────────────────
    seller = _text_or_none(soup.select_one("#sellerProfileTriggerId")) or None
    if not seller:
        merchant = soup.find("div", id="merchant-info")
        if merchant:
            m = re.search(r"sold by\s+(.+?)(?:\s+and|\.|$)", merchant.get_text(" ", strip=True), re.I)
            seller = m.group(1).strip() if m else None

    # ── Feature bullets ───────────────────────────────────────
    features: List[str] = []
    bullets = soup.select("#feature-bullets li span.a-list-item")
    for b in bullets[:8]:
        text = b.get_text(strip=True)
        if text and len(text) > 3:
            features.append(text)

    # ── Breadcrumbs (category path) ───────────────────────────
    breadcrumbs = [
        a.get_text(strip=True)
        for a in soup.select("#wayfinding-breadcrumbs_feature_div li a")
        if a.get_text(strip=True)
    ][:6]

    # ── Image gallery ─────────────────────────────────────────
    image_url: Optional[str] = None
    images: List[str] = []
    img_tag = soup.find("img", id="landingImage") or soup.find("img", id="imgBlkFront")
    if img_tag:
        image_url = img_tag.get("data-old-hires") or img_tag.get("src")
    for m in re.finditer(r'"hiRes":"(https://[^"]+)"', html):
        if m.group(1) not in images:
            images.append(m.group(1))
        if len(images) >= 6:
            break
    if not image_url and images:
        image_url = images[0]

    return {
        **_base_result("amazon", url),
        "asin":           asin,
        "title":          title,
        "brand":          brand,
        "price":          price,
        "list_price":     list_price,
        "discount_pct":   _discount_pct(price, list_price),
        "currency":       _currency_for_domain(domain, AMAZON_CURRENCY_MAP, "USD"),
        "in_stock":       in_stock,
        "availability":   avail_text or None,
        "rating":         rating,
        "review_count":   review_count,
        "seller":         seller,
        "features":       features or None,
        "categories":     breadcrumbs or None,
        "image_url":      image_url,
        "images":         images or None,
    }


async def scrape_meesho(url: str) -> Dict[str, Any]:
    """Meesho: title, price, discount, delivery info, rating via JSON-LD + CSS."""
    html = await _fetch_html(url)
    soup = BeautifulSoup(html, "html.parser")
    ld = extract_json_ld_product(soup)

    title = ld.get("title") or _text_or_none(
        soup.find("h1", class_=re.compile(r"product.*title|title.*product", re.I))
        or soup.find("span", class_=re.compile(r"ProductTitle", re.I))
        or soup.find("h1")
    )

    price = ld.get("price")
    if price is None:
        price_tag = (
            soup.find("h4", class_=re.compile(r"selling.*price|price", re.I))
            or soup.find("span", class_=re.compile(r"pdp-price|price", re.I))
        )
        price = _clean_price(_text_or_none(price_tag) or "")

    original_tag = soup.find("span", class_=re.compile(r"strike|original.*price|mrp", re.I))
    original_price = _clean_price(_text_or_none(original_tag) or "")

    oos_tag = soup.find(string=re.compile(r"out of stock|sold out", re.I))
    in_stock = ld.get("in_stock") if ld.get("in_stock") is not None else oos_tag is None

    delivery_info = _text_or_none(soup.find("p", class_=re.compile(r"delivery|ship", re.I)))

    image_url = ld.get("image_url") or (
        (soup.find("img", class_=re.compile(r"product.*image|img.*product", re.I)) or {}).get("src")
        if soup.find("img", class_=re.compile(r"product.*image|img.*product", re.I)) else None
    ) or _meta_content(soup, "og:image")

    return {
        **_base_result("meesho", url),
        "title":          title,
        "price":          price,
        "original_price": original_price,
        "discount_pct":   _discount_pct(price, original_price),
        "currency":       "INR",
        "in_stock":       in_stock,
        "rating":         ld.get("rating"),
        "review_count":   ld.get("review_count"),
        "delivery_info":  delivery_info,
        "image_url":      image_url,
    }


async def scrape_flipkart(url: str) -> Dict[str, Any]:
    """Flipkart: JSON-LD first, then class-pattern CSS fallbacks."""
    html = await _fetch_html(url)
    soup = BeautifulSoup(html, "html.parser")
    ld = extract_json_ld_product(soup)

    title = ld.get("title") or _text_or_none(
        soup.find("span", class_=re.compile(r"B_NuCI|VU-ZEz", re.I))
        or soup.find("h1", class_=re.compile(r"yhB1nd|_6EBuvT", re.I))
        or soup.find("h1")
    )

    price = ld.get("price")
    if price is None:
        price_tag = soup.find("div", class_=re.compile(r"_30jeq3|Nx9bqj|_16Jk6d", re.I))
        price = _clean_price(_text_or_none(price_tag) or "")

    mrp_tag = soup.find("div", class_=re.compile(r"_3I9_wc|yRaY8j", re.I))
    original_price = _clean_price(_text_or_none(mrp_tag) or "")

    discount_tag = soup.find("div", class_=re.compile(r"_3Ay6Sb|UkUFwK", re.I))
    discount_raw = _text_or_none(discount_tag)

    oos_tag = soup.find(class_=re.compile(r"_16FRp0", re.I))
    in_stock = ld.get("in_stock") if ld.get("in_stock") is not None else oos_tag is None

    rating = ld.get("rating")
    if rating is None:
        rating_tag = soup.find("div", class_=re.compile(r"_3LWZlK|XQDdHH", re.I))
        try:
            rating = float(rating_tag.get_text(strip=True)) if rating_tag else None
        except ValueError:
            rating = None

    return {
        **_base_result("flipkart", url),
        "title":          title,
        "brand":          ld.get("brand"),
        "price":          price,
        "original_price": original_price,
        "discount":       discount_raw,
        "discount_pct":   _discount_pct(price, original_price),
        "currency":       "INR",
        "in_stock":       in_stock,
        "rating":         rating,
        "review_count":   ld.get("review_count"),
        "image_url":      ld.get("image_url") or _meta_content(soup, "og:image"),
    }


async def scrape_ebay(url: str) -> Dict[str, Any]:
    """eBay (global storefronts): JSON-LD + listing-specific selectors."""
    html = await _fetch_html(url)
    soup = BeautifulSoup(html, "html.parser")
    ld = extract_json_ld_product(soup)
    domain = _domain_of(url)

    title = ld.get("title") or _text_or_none(
        soup.select_one("h1.x-item-title__mainTitle span") or soup.find("h1")
    )

    price = ld.get("price")
    if price is None:
        price_tag = soup.select_one("div.x-price-primary span.ux-textspans") or soup.find(
            "span", attrs={"itemprop": "price"}
        )
        price = _clean_price(_text_or_none(price_tag) or "")

    condition = _text_or_none(
        soup.select_one("div.x-item-condition-text span.ux-textspans")
        or soup.find("div", class_=re.compile(r"condText", re.I))
    )

    seller = ld.get("seller") or _text_or_none(
        soup.select_one("div.x-sellercard-atf__info__about-seller a span")
    )

    shipping = _text_or_none(
        soup.select_one("div.ux-labels-values--shipping span.ux-textspans--BOLD")
    )

    sold_tag = soup.find(string=re.compile(r"[\d,]+\s+sold", re.I))
    items_sold = _parse_int(str(sold_tag)) if sold_tag else None

    return {
        **_base_result("ebay", url),
        "title":        title,
        "brand":        ld.get("brand"),
        "price":        price,
        "currency":     ld.get("currency") or _currency_for_domain(domain, EBAY_CURRENCY_MAP, "USD"),
        "in_stock":     ld.get("in_stock", True),
        "condition":    condition,
        "seller":       seller,
        "shipping":     shipping,
        "items_sold":   items_sold,
        "rating":       ld.get("rating"),
        "review_count": ld.get("review_count"),
        "image_url":    ld.get("image_url") or _meta_content(soup, "og:image"),
        "images":       ld.get("images"),
    }


async def scrape_walmart(url: str) -> Dict[str, Any]:
    """Walmart: JSON-LD is reliably embedded; selectors as fallback."""
    html = await _fetch_html(url)
    soup = BeautifulSoup(html, "html.parser")
    ld = extract_json_ld_product(soup)

    title = ld.get("title") or _text_or_none(
        soup.find("h1", attrs={"itemprop": "name"}) or soup.find("h1")
    )

    price = ld.get("price")
    if price is None:
        price_tag = soup.find("span", attrs={"itemprop": "price"}) or soup.find(
            "span", attrs={"data-testid": "price-wrap"}
        )
        price = _clean_price(_text_or_none(price_tag) or "")

    return {
        **_base_result("walmart", url),
        "title":        title,
        "brand":        ld.get("brand"),
        "price":        price,
        "currency":     ld.get("currency") or "USD",
        "in_stock":     ld.get("in_stock", price is not None),
        "seller":       ld.get("seller"),
        "rating":       ld.get("rating"),
        "review_count": ld.get("review_count"),
        "description":  ld.get("description"),
        "image_url":    ld.get("image_url") or _meta_content(soup, "og:image"),
        "images":       ld.get("images"),
    }


async def scrape_aliexpress(url: str) -> Dict[str, Any]:
    """
    AliExpress: heavily JS-rendered. Strategy: runParams JSON blob →
    JSON-LD → OpenGraph meta fallbacks.
    """
    html = await _fetch_html(url)
    soup = BeautifulSoup(html, "html.parser")
    ld = extract_json_ld_product(soup)

    title = ld.get("title")
    price = ld.get("price")
    currency = ld.get("currency")
    rating = ld.get("rating")
    review_count = ld.get("review_count")
    orders: Optional[int] = None

    # window.runParams blob (legacy + current PDP)
    m = re.search(r'"formatedActivityPrice":"([^"]+)"', html) or re.search(r'"formatedPrice":"([^"]+)"', html)
    if price is None and m:
        price = _clean_price(m.group(1))
    m = re.search(r'"currencyCode":"([A-Z]{3})"', html)
    if not currency and m:
        currency = m.group(1)
    m = re.search(r'"averageStar":"?([\d.]+)"?', html)
    if rating is None and m:
        try:
            rating = float(m.group(1))
        except ValueError:
            pass
    m = re.search(r'"tradeCount":"?(\d+)"?', html)
    if m:
        orders = int(m.group(1))
    m = re.search(r'"subject":"([^"]+)"', html)
    if not title and m:
        title = m.group(1)

    if not title:
        title = _meta_content(soup, "og:title")

    return {
        **_base_result("aliexpress", url),
        "title":        title,
        "brand":        ld.get("brand"),
        "price":        price,
        "currency":     currency or "USD",
        "in_stock":     ld.get("in_stock", True),
        "rating":       rating,
        "review_count": review_count,
        "orders":       orders,
        "image_url":    ld.get("image_url") or _meta_content(soup, "og:image"),
    }


async def scrape_myntra(url: str) -> Dict[str, Any]:
    """Myntra: parse the embedded window.__myx PDP state blob."""
    html = await _fetch_html(url)
    soup = BeautifulSoup(html, "html.parser")

    title = brand = None
    price = mrp = None
    rating: Optional[float] = None
    rating_count: Optional[int] = None
    image_url: Optional[str] = None

    m = re.search(r"window\.__myx\s*=\s*(\{.*?\});?\s*</script>", html, re.DOTALL)
    if m:
        try:
            state = json.loads(m.group(1))
            pdp = state.get("pdpData", {}) or {}
            title = pdp.get("name")
            brand = (pdp.get("brand") or {}).get("name")
            price_block = pdp.get("price") or {}
            price = price_block.get("discounted")
            mrp = price_block.get("mrp")
            ratings = pdp.get("ratings") or {}
            rating = ratings.get("averageRating")
            rating_count = ratings.get("totalCount")
            media = (pdp.get("media") or {}).get("albums") or []
            if media and media[0].get("images"):
                image_url = (media[0]["images"][0] or {}).get("imageURL")
        except (json.JSONDecodeError, AttributeError, IndexError, TypeError):
            pass

    if not title:
        ld = extract_json_ld_product(soup)
        title = ld.get("title") or _meta_content(soup, "og:title")
        brand = brand or ld.get("brand")
        price = price if price is not None else ld.get("price")
        rating = rating if rating is not None else ld.get("rating")
        image_url = image_url or ld.get("image_url") or _meta_content(soup, "og:image")

    try:
        rating = round(float(rating), 2) if rating is not None else None
    except (TypeError, ValueError):
        rating = None

    return {
        **_base_result("myntra", url),
        "title":          title,
        "brand":          brand,
        "price":          float(price) if price is not None else None,
        "original_price": float(mrp) if mrp is not None else None,
        "discount_pct":   _discount_pct(price, mrp),
        "currency":       "INR",
        "in_stock":       price is not None,
        "rating":         rating,
        "review_count":   rating_count,
        "image_url":      image_url,
    }


async def scrape_ajio(url: str) -> Dict[str, Any]:
    """Ajio: JSON-LD + __PRELOADED_STATE__ price extraction."""
    html = await _fetch_html(url)
    soup = BeautifulSoup(html, "html.parser")
    ld = extract_json_ld_product(soup)

    title = ld.get("title") or _meta_content(soup, "og:title")
    brand = ld.get("brand")
    price = ld.get("price")
    original_price: Optional[float] = None

    m = re.search(r'"wasPriceData":\{[^}]*?"value":([\d.]+)', html)
    if m:
        original_price = float(m.group(1))
    if price is None:
        m = re.search(r'"prices?":\{[^}]*?"value":([\d.]+)', html)
        if m:
            price = float(m.group(1))

    return {
        **_base_result("ajio", url),
        "title":          title,
        "brand":          brand,
        "price":          price,
        "original_price": original_price,
        "discount_pct":   _discount_pct(price, original_price),
        "currency":       ld.get("currency") or "INR",
        "in_stock":       ld.get("in_stock", price is not None),
        "rating":         ld.get("rating"),
        "review_count":   ld.get("review_count"),
        "image_url":      ld.get("image_url") or _meta_content(soup, "og:image"),
    }


# ── Scraper registry — single source of routing truth ────────
SCRAPER_REGISTRY: Dict[str, Callable[[str], Awaitable[Dict[str, Any]]]] = {
    "amazon":     scrape_amazon,
    "meesho":     scrape_meesho,
    "flipkart":   scrape_flipkart,
    "ebay":       scrape_ebay,
    "walmart":    scrape_walmart,
    "aliexpress": scrape_aliexpress,
    "myntra":     scrape_myntra,
    "ajio":       scrape_ajio,
}


# ──────────────────────────────────────────────────────────────────────────────
#  SECTION 10 — SHORTLINK RESOLUTION & PLATFORM DETECTION
# ──────────────────────────────────────────────────────────────────────────────

def _extract_asin_from_url(url: str) -> Optional[str]:
    """
    Extract ASIN from any Amazon URL pattern:
      /dp/ASIN · /gp/product/ASIN · /gp/aw/d/ASIN ·
      /exec/obidos/ASIN/ · /o/ASIN/ · ?asin=ASIN
    """
    asin_patterns = [
        r"/(?:dp|gp/product|gp/aw/d|exec/obidos/ASIN|o)/([A-Z0-9]{10})",
        r"[?&]asin=([A-Z0-9]{10})",
        r"/([A-Z0-9]{10})(?:[/?#]|$)",
    ]
    for pat in asin_patterns:
        m = re.search(pat, url, re.IGNORECASE)
        if m:
            candidate = m.group(1).upper()
            if re.fullmatch(r"[A-Z0-9]{10}", candidate):
                return candidate
    return None


def _canonicalize_amazon_url(url: str) -> str:
    """
    Strip tracking noise; return a clean canonical /dp/<ASIN> URL on the
    same domain. Preserves the `tag` (affiliate) param if present.
    """
    parsed = urlparse(url)

    asin = _extract_asin_from_url(url)
    if asin:
        qs = parse_qs(parsed.query)
        tag = qs.get("tag", [None])[0]
        query = f"tag={tag}" if tag else ""
        return urlunparse((parsed.scheme, parsed.netloc, f"/dp/{asin}", "", query, ""))

    qs = parse_qs(parsed.query, keep_blank_values=False)
    clean_qs = {k: v for k, v in qs.items() if k not in _STRIP_PARAMS}
    tag = qs.get("tag", [None])[0]
    if tag:
        clean_qs["tag"] = [tag]
    flat_qs = "&".join(f"{k}={v[0]}" for k, v in clean_qs.items())
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", flat_qs, ""))


def _detect_platform_from_resolved(url: str) -> str:
    """Route a fully-resolved URL to the correct scraper."""
    domain = _domain_of(url)
    if _is_amazon_retail(url) or _is_amazon_shortlink(url):
        return "amazon"
    if _domain_matches(domain, EBAY_DOMAINS):
        return "ebay"
    if _domain_matches(domain, WALMART_DOMAINS):
        return "walmart"
    if _domain_matches(domain, ALIEXPRESS_DOMAINS):
        return "aliexpress"
    if _domain_matches(domain, MYNTRA_DOMAINS):
        return "myntra"
    if _domain_matches(domain, AJIO_DOMAINS):
        return "ajio"
    if "meesho.com" in domain:
        return "meesho"
    if "flipkart.com" in domain or "fkrt.it" in domain or "dl.flipkart.com" in domain:
        return "flipkart"
    return "unknown"


def _detect_platform(url: str) -> str:
    """Legacy alias kept for backward compat with internal callers."""
    return _detect_platform_from_resolved(url)


# Domains that are redirectors and must be resolved before scraping
_REDIRECTOR_DOMAINS: frozenset = frozenset(
    set(AMAZON_SHORTLINK_DOMAINS) | {"fkrt.it", "dl.flipkart.com", "a.aliexpress.com", "ebay.us"}
)


def _needs_resolution(url: str) -> bool:
    return _domain_matches(_domain_of(url), _REDIRECTOR_DOMAINS)


async def resolve_url(raw_url: str) -> Tuple[str, str]:
    """
    Resolve any URL (including shortlinks) to its final destination.

    Returns:  (resolved_url, platform_hint)

    Raises:
        HTTPException 422 – URL never resolves to a supported platform
        HTTPException 504 – Redirect chain timed out / network error
    """
    if not raw_url.startswith(("http://", "https://")):
        raw_url = "https://" + raw_url

    if _needs_resolution(raw_url):
        try:
            http = get_http_client()
            try:
                resp = await http.head(raw_url, headers=build_scrape_headers(), timeout=SCRAPE_TIMEOUT)
                if resp.status_code >= 400:
                    resp = await http.get(raw_url, headers=build_scrape_headers(), timeout=SCRAPE_TIMEOUT)
            except httpx.HTTPStatusError:
                resp = await http.get(raw_url, headers=build_scrape_headers(), timeout=SCRAPE_TIMEOUT)
            resolved = str(resp.url)
        except httpx.TimeoutException:
            raise HTTPException(
                status_code=504,
                detail={
                    "error":        "SHORTLINK_TIMEOUT",
                    "message":      f"Timed out resolving shortlink: {raw_url}",
                    "original_url": raw_url,
                },
            )
        except httpx.TooManyRedirects:
            raise HTTPException(
                status_code=422,
                detail={
                    "error":        "REDIRECT_LOOP",
                    "message":      f"Redirect loop detected for: {raw_url}",
                    "original_url": raw_url,
                },
            )
        except httpx.RequestError as exc:
            raise HTTPException(
                status_code=504,
                detail={
                    "error":        "SHORTLINK_RESOLUTION_FAILED",
                    "message":      str(exc),
                    "original_url": raw_url,
                },
            )
    else:
        resolved = raw_url

    if _is_amazon_retail(resolved):
        resolved = _canonicalize_amazon_url(resolved)

    platform = _detect_platform_from_resolved(resolved)
    return resolved, platform


# ──────────────────────────────────────────────────────────────────────────────
#  SECTION 11 — USAGE ANALYTICS  (per-client, in-process)
# ──────────────────────────────────────────────────────────────────────────────

class ClientUsage:
    __slots__ = ("requests", "cache_hits", "errors", "latency_sum",
                 "latency_n", "platforms", "first_seen", "last_seen")

    def __init__(self) -> None:
        self.requests: int = 0
        self.cache_hits: int = 0
        self.errors: int = 0
        self.latency_sum: float = 0.0
        self.latency_n: int = 0
        self.platforms: Dict[str, int] = defaultdict(int)
        self.first_seen: str = datetime.now(timezone.utc).isoformat()
        self.last_seen: str = self.first_seen

    def snapshot(self) -> Dict[str, Any]:
        return {
            "window":             "since_process_start",
            "requests":           self.requests,
            "errors":             self.errors,
            "cache_hits":         self.cache_hits,
            "cache_hit_ratio":    round(self.cache_hits / self.requests, 3) if self.requests else 0.0,
            "avg_latency_ms":     round(self.latency_sum / self.latency_n, 1) if self.latency_n else 0.0,
            "platform_breakdown": dict(self.platforms),
            "first_seen":         self.first_seen,
            "last_seen":          self.last_seen,
        }


CLIENT_ANALYTICS: Dict[str, ClientUsage] = defaultdict(ClientUsage)


def _record_usage(
    client_id: str,
    platform: str,
    latency_ms: float,
    cache_hit: bool,
    success: bool,
) -> None:
    usage = CLIENT_ANALYTICS[client_id]
    usage.requests += 1
    usage.last_seen = datetime.now(timezone.utc).isoformat()
    usage.platforms[platform] += 1
    if cache_hit:
        usage.cache_hits += 1
    else:
        usage.latency_sum += latency_ms
        usage.latency_n += 1
    if not success:
        usage.errors += 1
    METRICS.platform_counts[platform] += 1
    if success:
        METRICS.scrapes_ok += 1
    else:
        METRICS.scrapes_failed += 1
    if not cache_hit:
        METRICS.observe_latency(latency_ms)


async def _persist_usage_event(client_id: str, platform: str, url: str, latency_ms: float, cache_hit: bool) -> None:
    """Best-effort durable analytics (only if `usage_events` table exists)."""
    try:
        supabase.table("usage_events").insert({
            "id":         str(uuid.uuid4()),
            "client_id":  client_id,
            "platform":   platform,
            "url":        url[:500],
            "latency_ms": round(latency_ms),
            "cache_hit":  cache_hit,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }).execute()
    except Exception:
        pass  # table optional — analytics must never break the request path


# ──────────────────────────────────────────────────────────────────────────────
#  SECTION 12 — SCRAPE ORCHESTRATOR  (cache → resolve → scrape)
# ──────────────────────────────────────────────────────────────────────────────

SUPPORTED_PLATFORM_SUMMARY = (
    "Amazon (incl. shortlinks amzn.to, amzn.in, amzn.eu, a.co, amzn.asia, "
    "z.cn, amzn.me), Flipkart, Meesho, eBay, Walmart, AliExpress, Myntra, Ajio"
)


def _validate_supported_domain(domain: str) -> bool:
    return (
        _domain_matches(domain, AMAZON_SHORTLINK_DOMAINS)
        or _domain_matches(domain, AMAZON_RETAIL_DOMAINS)
        or _domain_matches(domain, EBAY_DOMAINS)
        or _domain_matches(domain, WALMART_DOMAINS)
        or _domain_matches(domain, ALIEXPRESS_DOMAINS)
        or _domain_matches(domain, MYNTRA_DOMAINS)
        or _domain_matches(domain, AJIO_DOMAINS)
        or "meesho.com" in domain
        or "flipkart.com" in domain
        or "fkrt.it" in domain
    )


def _scrape_error_to_http(exc: Exception, resolved_url: str) -> HTTPException:
    """Translate engine-level failures into precise API errors."""
    if isinstance(exc, CircuitOpen):
        return HTTPException(
            status_code=503,
            detail={
                "error":   "CIRCUIT_OPEN",
                "message": f"Target {exc} is temporarily rejecting our traffic. Cooling down — retry in ~30s.",
            },
        )
    if isinstance(exc, BotChallengeDetected):
        return HTTPException(
            status_code=503,
            detail={
                "error":   "BOT_CHALLENGE",
                "message": "Target served a bot challenge after identity rotation. Retry shortly.",
            },
        )
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        if status == 403:
            return HTTPException(
                status_code=503,
                detail={"error": "SCRAPE_BLOCKED", "message": "Target blocked the request. Retry."},
            )
        if status in (404, 410):
            return HTTPException(
                status_code=404,
                detail={"error": "PRODUCT_NOT_FOUND", "message": "Product page returned 404."},
            )
        return HTTPException(
            status_code=502,
            detail={"error": "UPSTREAM_ERROR", "message": f"Target returned HTTP {status}."},
        )
    if isinstance(exc, httpx.RequestError):
        logger.error("Network error scraping %s: %s", resolved_url, exc)
        return HTTPException(
            status_code=504,
            detail={"error": "NETWORK_TIMEOUT", "message": "Request to target timed out."},
        )
    logger.exception("Unexpected scrape failure for %s", resolved_url)
    return HTTPException(
        status_code=500,
        detail={"error": "SCRAPE_FAILED", "message": "Unexpected extraction failure."},
    )


async def execute_scrape(resolved_url: str, platform: str, fresh: bool) -> Tuple[Dict[str, Any], bool]:
    """
    Cache-aware scrape execution.
    Returns: (data, cache_hit)
    """
    cache_key = f"{platform}::{resolved_url}"
    if not fresh:
        cached = SCRAPE_CACHE.get(cache_key)
        if cached is not None:
            METRICS.cache_hits += 1
            return cached, True
    METRICS.cache_misses += 1

    scraper = SCRAPER_REGISTRY.get(platform)
    if scraper is None:
        raise HTTPException(
            status_code=422,
            detail={
                "error":        "UNSUPPORTED_PLATFORM",
                "message":      f"Platform not supported. Supported: {SUPPORTED_PLATFORM_SUMMARY}",
                "resolved_url": resolved_url,
            },
        )

    data = await scraper(resolved_url)
    SCRAPE_CACHE.set(cache_key, data)
    return data, False


# ──────────────────────────────────────────────────────────────────────────────
#  SECTION 13 — PUBLIC API MODELS
# ──────────────────────────────────────────────────────────────────────────────

class PulseRequest(BaseModel):
    url: str
    fresh: bool = Field(
        default=False,
        description="Bypass the response cache and force a live scrape.",
    )

    @field_validator("url")
    @classmethod
    def must_be_supported_platform(cls, v: str) -> str:
        normalised = v if v.startswith(("http://", "https://")) else "https://" + v
        domain = _domain_of(normalised)
        if not _validate_supported_domain(domain):
            raise ValueError(f"URL must be from a supported platform: {SUPPORTED_PLATFORM_SUMMARY}.")
        return v


class BatchRequest(BaseModel):
    urls: List[str] = Field(..., min_length=1, max_length=100)
    fresh: bool = False

    @field_validator("urls")
    @classmethod
    def all_urls_supported(cls, v: List[str]) -> List[str]:
        for u in v:
            normalised = u if u.startswith(("http://", "https://")) else "https://" + u
            if not _validate_supported_domain(_domain_of(normalised)):
                raise ValueError(f"Unsupported platform URL: {u}. Supported: {SUPPORTED_PLATFORM_SUMMARY}.")
        return v


# ──────────────────────────────────────────────────────────────────────────────
#  SECTION 14 — PUBLIC API ENDPOINTS
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/", include_in_schema=False)
async def root():
    return {
        "service":   "TitanFlow Data API",
        "status":    "operational",
        "version":   SERVICE_VERSION,
        "platforms": sorted(SCRAPER_REGISTRY.keys()),
        "docs":      "/docs",
    }


@app.get("/health", include_in_schema=False)
async def health():
    """Uptime probe — no auth required."""
    return {
        "status":  "ok",
        "version": SERVICE_VERSION,
        "ts":      datetime.now(timezone.utc).isoformat(),
        "uptime_seconds": round((datetime.now(timezone.utc) - STARTED_AT).total_seconds()),
    }


@app.get("/metrics", tags=["Ops"], summary="Operational metrics")
async def metrics():
    """In-process operational metrics (counts, cache ratio, latency)."""
    snap = METRICS.snapshot()
    snap["cache"]["entries"] = len(SCRAPE_CACHE)
    snap["circuit_breaker_open_domains"] = BREAKER.open_domains()
    return snap


@app.get("/v1/platforms", tags=["Data"], summary="List supported platforms")
async def platforms():
    """Public capability discovery endpoint."""
    return {
        "platforms": [
            {"id": "amazon",     "regions": len(AMAZON_RETAIL_DOMAINS), "shortlinks": sorted(AMAZON_SHORTLINK_DOMAINS)},
            {"id": "flipkart",   "regions": 1, "shortlinks": ["fkrt.it", "dl.flipkart.com"]},
            {"id": "meesho",     "regions": 1, "shortlinks": []},
            {"id": "ebay",       "regions": len(EBAY_DOMAINS), "shortlinks": ["ebay.us"]},
            {"id": "walmart",    "regions": len(WALMART_DOMAINS), "shortlinks": []},
            {"id": "aliexpress", "regions": len(ALIEXPRESS_DOMAINS), "shortlinks": ["a.aliexpress.com"]},
            {"id": "myntra",     "regions": 1, "shortlinks": []},
            {"id": "ajio",       "regions": 1, "shortlinks": []},
        ],
    }


@app.get("/v1/plans", tags=["Account"], summary="List subscription plans")
async def plans():
    """Public plan matrix for upgrade decisions."""
    return {
        "plans": [
            {
                "id":             plan_id,
                "label":          cfg["label"],
                "monthly_quota":  cfg["monthly_quota"] or "unlimited",
                "rate_limit":     cfg["rate_limit"],
                "batch_max_urls": cfg["batch_max_urls"],
            }
            for plan_id, cfg in PLANS.items()
        ],
        "upgrade_url": STRIPE_CHECKOUT_URL,
    }


@app.post(
    "/v1/pulse",
    summary="Scrape a product URL",
    description=(
        "Pass any Amazon, Flipkart, Meesho, eBay, Walmart, AliExpress, "
        "Myntra, or Ajio product URL. TitanFlow resolves shortlinks, "
        "scrapes in real time (or serves from the smart cache), and "
        "returns structured product data."
    ),
    tags=["Data"],
)
@limiter.limit("120/minute")
async def pulse(
    request: Request,
    body: PulseRequest,
    background_tasks: BackgroundTasks,
    client: AuthenticatedClient = Depends(verify_api_key),
):
    """
    **POST /v1/pulse**

    - Requires `X-Api-Key` header.
    - Free tier: 1 000 requests/month · Pro/Enterprise: unlimited.
    - Accepts full product URLs **and** shortlinks (`amzn.to`, `a.co`,
      `fkrt.it`, `a.aliexpress.com`, …) — transparently resolved and
      canonicalized before scraping.
    - Responses are cached (default 300 s). Pass `"fresh": true` to
      force a live scrape.
    """
    start_ms     = time.monotonic()
    original_url = body.url

    # ── Step 1: Resolve shortlinks / canonicalize ─────────────
    resolved_url, platform = await resolve_url(original_url)
    was_shortlink = _needs_resolution(original_url)
    logger.info(
        "URL resolved | rid=%s original=%s resolved=%s platform=%s shortlink=%s",
        getattr(request.state, "request_id", "-"), original_url, resolved_url, platform, was_shortlink,
    )

    # ── Step 2: Scrape (cache-aware) ──────────────────────────
    try:
        data, cache_hit = await execute_scrape(resolved_url, platform, body.fresh)
    except HTTPException:
        _record_usage(client.id, platform, 0.0, False, success=False)
        raise
    except Exception as exc:
        _record_usage(client.id, platform, 0.0, False, success=False)
        raise _scrape_error_to_http(exc, resolved_url)

    elapsed_ms = round((time.monotonic() - start_ms) * 1000)
    _record_usage(client.id, platform, elapsed_ms, cache_hit, success=True)
    background_tasks.add_task(_persist_usage_event, client.id, platform, resolved_url, elapsed_ms, cache_hit)

    # ── Step 3: Build response (v1.x-compatible shape) ────────
    resolution_meta: Dict[str, Any] = {}
    if was_shortlink:
        resolution_meta = {
            "shortlink_resolved": True,
            "original_url":       original_url,
            "resolved_url":       resolved_url,
        }

    return {
        "success":    True,
        "client_id":  client.id,
        "latency_ms": elapsed_ms,
        "cache_hit":  cache_hit,
        **({"resolution": resolution_meta} if resolution_meta else {}),
        "data":       data,
    }


@app.get("/v1/account", summary="Get account usage", tags=["Account"])
async def account(client: AuthenticatedClient = Depends(verify_api_key)):
    """Return the authenticated client's quota and plan details."""
    quota = client.plan_config["monthly_quota"]
    remaining = "unlimited" if quota is None else max(0, quota - client.requests_this_month)
    return {
        "email":               client.email,
        "plan":                client.plan,
        "plan_label":          client.plan_config["label"],
        "requests_this_month": client.requests_this_month,
        "monthly_limit":       "unlimited" if quota is None else quota,
        "requests_remaining":  remaining,
        "rate_limit":          client.plan_config["rate_limit"],
        "batch_max_urls":      client.plan_config["batch_max_urls"],
        "upgrade_url":         None if client.plan != "free" else STRIPE_CHECKOUT_URL,
    }


@app.get("/v1/account/usage", summary="Usage analytics", tags=["Account"])
async def account_usage(client: AuthenticatedClient = Depends(verify_api_key)):
    """
    Per-client analytics: request volume, error rate, cache hit ratio,
    average live-scrape latency, and platform breakdown.
    """
    usage = CLIENT_ANALYTICS.get(client.id)
    return {
        "email":     client.email,
        "plan":      client.plan,
        "analytics": usage.snapshot() if usage else ClientUsage().snapshot(),
    }


# ──────────────────────────────────────────────────────────────────────────────
#  SECTION 15 — ASYNC BATCH JOB QUEUE
# ──────────────────────────────────────────────────────────────────────────────

JOB_STORE: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
JOB_STORE_MAX = 1_000


def _evict_old_jobs() -> None:
    while len(JOB_STORE) > JOB_STORE_MAX:
        JOB_STORE.popitem(last=False)


async def _process_batch_job(job_id: str, urls: List[str], fresh: bool, client_id: str) -> None:
    """Background batch processor with bounded concurrency."""
    job = JOB_STORE.get(job_id)
    if job is None:
        return
    job["status"] = "processing"
    semaphore = asyncio.Semaphore(BATCH_CONCURRENCY)

    async def worker(index: int, url: str) -> None:
        async with semaphore:
            item_start = time.monotonic()
            try:
                resolved, platform = await resolve_url(url)
                data, cache_hit = await execute_scrape(resolved, platform, fresh)
                elapsed = round((time.monotonic() - item_start) * 1000)
                _record_usage(client_id, platform, elapsed, cache_hit, success=True)
                job["results"][index] = {
                    "url": url, "success": True, "cache_hit": cache_hit,
                    "latency_ms": elapsed, "data": data,
                }
            except HTTPException as exc:
                _record_usage(client_id, "unknown", 0.0, False, success=False)
                detail = exc.detail if isinstance(exc.detail, dict) else {"message": str(exc.detail)}
                job["results"][index] = {"url": url, "success": False, "status": exc.status_code, **detail}
            except Exception as exc:
                _record_usage(client_id, "unknown", 0.0, False, success=False)
                http_exc = _scrape_error_to_http(exc, url)
                detail = http_exc.detail if isinstance(http_exc.detail, dict) else {"message": str(http_exc.detail)}
                job["results"][index] = {"url": url, "success": False, "status": http_exc.status_code, **detail}
            finally:
                job["completed"] += 1

    await asyncio.gather(*(worker(i, u) for i, u in enumerate(urls)))
    job["status"] = "completed"
    job["finished_at"] = datetime.now(timezone.utc).isoformat()
    logger.info("Batch job %s completed (%d urls).", job_id, len(urls))


@app.post(
    "/v1/batch",
    summary="Submit a batch scrape job",
    tags=["Data"],
    status_code=202,
)
@limiter.limit("20/minute")
async def create_batch(
    request: Request,
    body: BatchRequest,
    client: AuthenticatedClient = Depends(verify_api_key),
):
    """
    **POST /v1/batch** — submit up to N product URLs (N depends on plan:
    Free 5 · Pro 25 · Enterprise 100). Returns a `job_id` immediately;
    poll `GET /v1/batch/{job_id}` for results.
    """
    max_urls = client.plan_config["batch_max_urls"]
    if len(body.urls) > max_urls:
        raise HTTPException(
            status_code=422,
            detail={
                "error":       "BATCH_TOO_LARGE",
                "message":     f"Your {client.plan_config['label']} plan allows up to {max_urls} URLs per batch.",
                "submitted":   len(body.urls),
                "limit":       max_urls,
                "upgrade_url": STRIPE_CHECKOUT_URL if client.plan == "free" else None,
            },
        )

    job_id = uuid.uuid4().hex
    JOB_STORE[job_id] = {
        "job_id":      job_id,
        "client_id":   client.id,
        "status":      "queued",
        "total":       len(body.urls),
        "completed":   0,
        "results":     [None] * len(body.urls),
        "created_at":  datetime.now(timezone.utc).isoformat(),
        "finished_at": None,
    }
    _evict_old_jobs()
    METRICS.batch_jobs_created += 1

    asyncio.create_task(_process_batch_job(job_id, body.urls, body.fresh, client.id))

    return {
        "success":    True,
        "job_id":     job_id,
        "status":     "queued",
        "total_urls": len(body.urls),
        "poll_url":   f"/v1/batch/{job_id}",
    }


@app.get("/v1/batch/{job_id}", summary="Get batch job status & results", tags=["Data"])
async def get_batch(job_id: str, client: AuthenticatedClient = Depends(verify_api_key)):
    job = JOB_STORE.get(job_id)
    if job is None or job["client_id"] != client.id:
        raise HTTPException(
            status_code=404,
            detail={"error": "JOB_NOT_FOUND", "message": "No such batch job for this account."},
        )
    return {
        "success":     True,
        "job_id":      job["job_id"],
        "status":      job["status"],
        "total":       job["total"],
        "completed":   job["completed"],
        "created_at":  job["created_at"],
        "finished_at": job["finished_at"],
        "results":     job["results"] if job["status"] == "completed" else [r for r in job["results"] if r],
    }


# ──────────────────────────────────────────────────────────────────────────────
#  SECTION 16 — AUTOMATED BILLING WEBHOOK  (idempotent)
# ──────────────────────────────────────────────────────────────────────────────

@app.post("/webhook/stripe", include_in_schema=False)
async def stripe_webhook(request: Request, background_tasks: BackgroundTasks):
    """
    Stripe sends a signed payload here on every billing event.

    Security: signature verified on the RAW request body via the
    official SDK (HMAC-SHA256 + constant-time compare inside).

    Idempotency: every event ID is recorded; replays are acknowledged
    with 200 but never reprocessed.

    Handles:
      • checkout.session.completed              → upgrade client to Pro
      • customer.subscription.deleted / paused  → downgrade to Free
      • invoice.payment_failed                  → log for ops follow-up
    """
    payload    = await request.body()
    sig_header = request.headers.get("stripe-signature", "")

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except stripe.error.SignatureVerificationError:
        logger.warning("Invalid Stripe webhook signature.")
        raise HTTPException(status_code=400, detail="Invalid signature.")
    except Exception as exc:
        logger.error("Webhook parse error: %s", exc)
        raise HTTPException(status_code=400, detail="Webhook error.")

    event_id   = event.get("id", "")
    event_type = event["type"]

    # ── Idempotency gate ──────────────────────────────────────
    if event_id and STRIPE_EVENTS.seen_before(event_id):
        METRICS.webhook_duplicates += 1
        logger.info("Duplicate Stripe event %s (%s) — acknowledged, skipped.", event_id, event_type)
        return {"received": True, "duplicate": True}

    METRICS.webhook_events += 1
    logger.info("Stripe event received: %s (%s)", event_type, event_id)

    if event_type == "checkout.session.completed":
        background_tasks.add_task(_handle_checkout_completed, event)
    elif event_type in ("customer.subscription.deleted", "customer.subscription.paused"):
        background_tasks.add_task(_handle_subscription_cancelled, event)
    elif event_type == "invoice.payment_failed":
        background_tasks.add_task(_handle_payment_failed, event)

    return {"received": True}


async def _handle_checkout_completed(event: Dict[str, Any]) -> None:
    """Upgrade client to Pro plan and reset their monthly counter."""
    session        = event["data"]["object"]
    customer_email = session.get("customer_email") or session.get("customer_details", {}).get("email")

    if not customer_email:
        logger.error("checkout.session.completed missing customer email: %s", session.get("id"))
        return

    update_payload: Dict[str, Any] = {"is_pro": True, "requests_this_month": 0}
    try:
        supabase.table("clients").update(update_payload).eq("email", customer_email).execute()
        logger.info("Upgraded %s to Pro.", customer_email)
    except Exception as exc:
        logger.error("Failed to upgrade %s: %s", customer_email, exc)


async def _handle_subscription_cancelled(event: Dict[str, Any]) -> None:
    """Downgrade client to Free plan when subscription lapses."""
    subscription = event["data"]["object"]
    customer_id  = subscription.get("customer")

    if not customer_id:
        return

    try:
        stripe_customer = stripe.Customer.retrieve(customer_id)
        email           = stripe_customer.get("email")
        if email:
            supabase.table("clients").update({"is_pro": False}).eq("email", email).execute()
            logger.info("Downgraded %s to Free.", email)
    except Exception as exc:
        logger.error("Failed to downgrade customer %s: %s", customer_id, exc)


async def _handle_payment_failed(event: Dict[str, Any]) -> None:
    """Log failed payments so ops can follow up before access lapses."""
    invoice = event["data"]["object"]
    email   = invoice.get("customer_email")
    logger.warning(
        "Payment FAILED | customer=%s invoice=%s amount_due=%s",
        email or invoice.get("customer"), invoice.get("id"), invoice.get("amount_due"),
    )


# ──────────────────────────────────────────────────────────────────────────────
#  SECTION 17 — ADMIN UTILITIES
# ──────────────────────────────────────────────────────────────────────────────

def require_admin(x_admin_secret: str = Header(...)) -> None:
    """Constant-time admin secret check."""
    if not ADMIN_SECRET or not hmac.compare_digest(x_admin_secret, ADMIN_SECRET):
        raise HTTPException(status_code=403, detail="Forbidden.")


class CreateClientRequest(BaseModel):
    email: str
    plan:  str = "free"

    @field_validator("plan")
    @classmethod
    def plan_must_exist(cls, v: str) -> str:
        if v.lower() not in PLANS:
            raise ValueError(f"plan must be one of: {', '.join(PLANS)}")
        return v.lower()


class SetPlanRequest(BaseModel):
    plan: str

    @field_validator("plan")
    @classmethod
    def plan_must_exist(cls, v: str) -> str:
        if v.lower() not in PLANS:
            raise ValueError(f"plan must be one of: {', '.join(PLANS)}")
        return v.lower()


@app.post(
    "/admin/clients",
    summary="Provision a new client",
    tags=["Admin"],
    dependencies=[Depends(require_admin)],
)
async def create_client_endpoint(body: CreateClientRequest):
    """
    Provision a new API client. Returns the generated API key.
    Store it safely — TitanFlow does not display it again.
    """
    new_key = uuid.uuid4().hex + uuid.uuid4().hex  # 64-char hex

    row: Dict[str, Any] = {
        "id":                  str(uuid.uuid4()),
        "email":               body.email,
        "api_key":             new_key,
        "is_pro":              body.plan in ("pro", "enterprise"),
        "requests_this_month": 0,
    }
    try:
        supabase.table("clients").insert(row).execute()
    except Exception as exc:
        logger.error("Client creation failed: %s", exc)
        raise HTTPException(
            status_code=500,
            detail={"error": "DB_ERROR", "message": "Could not create client."},
        )

    # Best-effort: persist explicit plan if the optional column exists
    if body.plan != "free":
        try:
            supabase.table("clients").update({"plan": body.plan}).eq("email", body.email).execute()
        except Exception:
            pass

    return {
        "message": "Client provisioned.",
        "email":   body.email,
        "plan":    body.plan,
        "api_key": new_key,
        "warning": "Save this key. It will not be shown again.",
    }


@app.get(
    "/admin/clients",
    summary="List clients (keys masked)",
    tags=["Admin"],
    dependencies=[Depends(require_admin)],
)
async def list_clients(limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0)):
    """Paginated client directory. API keys are never returned in full."""
    try:
        result = (
            supabase.table("clients")
            .select("*")
            .range(offset, offset + limit - 1)
            .execute()
        )
    except Exception as exc:
        raise HTTPException(status_code=503, detail={"error": "DB_UNAVAILABLE", "message": str(exc)})

    clients = []
    for row in result.data or []:
        clients.append({
            "id":                  row.get("id"),
            "email":               row.get("email"),
            "plan":                _resolve_plan(row),
            "requests_this_month": row.get("requests_this_month", 0),
            "api_key_masked":      _mask_key(row.get("api_key", "")),
        })
    return {"count": len(clients), "offset": offset, "clients": clients}


@app.delete(
    "/admin/clients/{email}",
    summary="Revoke a client",
    tags=["Admin"],
    dependencies=[Depends(require_admin)],
)
async def revoke_client(email: str):
    """Permanently remove a client and invalidate their API key."""
    try:
        supabase.table("clients").delete().eq("email", email).execute()
    except Exception as exc:
        raise HTTPException(status_code=500, detail={"error": "DB_ERROR", "message": str(exc)})
    return {"message": f"Client {email} revoked."}


@app.post(
    "/admin/clients/{email}/plan",
    summary="Change a client's plan",
    tags=["Admin"],
    dependencies=[Depends(require_admin)],
)
async def set_client_plan(email: str, body: SetPlanRequest):
    """Move a client between free / pro / enterprise tiers."""
    payload: Dict[str, Any] = {"is_pro": body.plan in ("pro", "enterprise")}
    try:
        supabase.table("clients").update(payload).eq("email", email).execute()
        try:  # optional `plan` column
            supabase.table("clients").update({"plan": body.plan}).eq("email", email).execute()
        except Exception:
            pass
    except Exception as exc:
        raise HTTPException(status_code=500, detail={"error": "DB_ERROR", "message": str(exc)})
    return {"message": f"Plan for {email} set to {body.plan}."}


@app.post(
    "/admin/reset-quota/{email}",
    summary="Manually reset a client's monthly quota",
    tags=["Admin"],
    dependencies=[Depends(require_admin)],
)
async def reset_quota(email: str):
    """Force-reset a client's monthly request counter to 0."""
    try:
        supabase.table("clients").update({"requests_this_month": 0}).eq("email", email).execute()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    return {"message": f"Quota reset for {email}."}


@app.post(
    "/admin/cache/purge",
    summary="Purge the scrape response cache",
    tags=["Admin"],
    dependencies=[Depends(require_admin)],
)
async def purge_cache():
    """Drop every cached scrape result (e.g. after a selector update)."""
    purged = SCRAPE_CACHE.purge()
    return {"message": "Cache purged.", "entries_removed": purged}


# ──────────────────────────────────────────────────────────────────────────────
#  SECTION 18 — GLOBAL ERROR HANDLERS
# ──────────────────────────────────────────────────────────────────────────────

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    detail = exc.detail if isinstance(exc.detail, dict) else {"message": exc.detail}
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success":    False,
            "status":     exc.status_code,
            "request_id": getattr(request.state, "request_id", None),
            **detail,
        },
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception on %s: %s", request.url.path, exc)
    return JSONResponse(
        status_code=500,
        content={
            "success":    False,
            "error":      "INTERNAL_ERROR",
            "message":    "An unexpected error occurred. Our team has been notified.",
            "request_id": getattr(request.state, "request_id", None),
        },
    )


# ──────────────────────────────────────────────────────────────────────────────
#  END OF FILE — TitanFlow Data API v2.0.0 "Atlas"
#  Run locally:   uvicorn main:app --host 0.0.0.0 --port 8000
# ──────────────────────────────────────────────────────────────────────────────
