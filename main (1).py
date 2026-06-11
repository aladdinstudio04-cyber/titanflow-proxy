# ============================================================
#  TitanFlow Data API  —  main.py
#  Enterprise-grade · Multi-tenant · SaaS-ready
#  Author: TitanFlow Engineering
#  Version: 1.1.0
#
#  v1.1.0 — Shortlink Resolution Engine
#    • Resolves all Amazon shortlink domains before scraping:
#      amzn.to, amzn.in, amzn.eu, amzn.com, amzn.asia,
#      a.co, z.cn, amzn.me, amzn.co.uk, amzn.co.jp
#    • Covers all 20 Amazon regional storefronts
#    • ASIN extraction & URL canonicalization (strips tracking noise,
#      preserves affiliate tag)
#    • Resolution metadata returned in API response
#    • PulseRequest validator updated to accept shortlink domains
# ============================================================

# ─────────────────────────────────────────────────────────────
#  SECTION 1 — CORE INITIALIZATION  (Lines 1 – 80)
# ─────────────────────────────────────────────────────────────

import os
import re
import hmac
import time
import uuid
import json
import hashlib
import logging
import asyncio
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Tuple
from urllib.parse import urlparse, urlunparse, urlencode, parse_qs

import httpx
from bs4 import BeautifulSoup
from supabase import create_client, Client
from fastapi import FastAPI, Request, Depends, HTTPException, Header, BackgroundTasks
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel, HttpUrl, field_validator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import stripe

# ── Logging ──────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("titanflow")

# ── Environment ───────────────────────────────────────────────
SUPABASE_URL: str       = os.environ["SUPABASE_URL"]
SUPABASE_KEY: str       = os.environ["SUPABASE_SERVICE_ROLE_KEY"]
STRIPE_SECRET_KEY: str  = os.environ["STRIPE_SECRET_KEY"]
STRIPE_WEBHOOK_SECRET: str = os.environ["STRIPE_WEBHOOK_SECRET"]
STRIPE_PRO_PRICE_ID: str   = os.environ.get("STRIPE_PRO_PRICE_ID", "")
STRIPE_CHECKOUT_URL: str   = os.environ.get("STRIPE_CHECKOUT_URL", "https://buy.stripe.com/titanflow-pro")

FREE_TIER_LIMIT: int = 1_000   # requests / month
SCRAPE_TIMEOUT:  int = 15      # seconds

# ── Clients ───────────────────────────────────────────────────
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
stripe.api_key   = STRIPE_SECRET_KEY

# ── Rate-limiter ──────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])

# ── App ───────────────────────────────────────────────────────
app = FastAPI(
    title="TitanFlow Data API",
    description=(
        "Real-time product intelligence for modern commerce teams. "
        "Supports all Amazon storefronts and shortlinks "
        "(amzn.to, amzn.in, amzn.eu, a.co, amzn.asia, z.cn, and more), "
        "Flipkart, and Meesho."
    ),
    version="1.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────────────────────────
#  SECTION 2 — DATABASE SECURITY LAYER  (Lines 81 – 200)
# ─────────────────────────────────────────────────────────────

class AuthenticatedClient(BaseModel):
    """Validated client attached to every protected request."""
    id:                   str
    email:                str
    api_key:              str
    is_pro:               bool
    requests_this_month:  int

    class Config:
        frozen = True


async def verify_api_key(x_api_key: str = Header(...)) -> AuthenticatedClient:
    """
    Dependency injected on every protected endpoint.

    1. Validates API key against Supabase `clients` table.
    2. Enforces free-tier quota (1 000 req / month).
    3. Increments request counter atomically via RPC.
    4. Returns a typed AuthenticatedClient or raises HTTP 401 / 402.
    """
    if not x_api_key or len(x_api_key) < 32:
        raise HTTPException(
            status_code=401,
            detail={
                "error":   "INVALID_API_KEY",
                "message": "Provide a valid X-Api-Key header.",
            },
        )

    try:
        result = (
            supabase.table("clients")
            .select("id, email, api_key, is_pro, requests_this_month")
            .eq("api_key", x_api_key)
            .single()
            .execute()
        )
    except Exception as exc:
        logger.error("Supabase lookup failed: %s", exc)
        raise HTTPException(
            status_code=503,
            detail={"error": "DB_UNAVAILABLE", "message": "Database unreachable. Retry shortly."},
        )

    client_row = result.data
    if not client_row:
        raise HTTPException(
            status_code=401,
            detail={"error": "UNAUTHORIZED", "message": "API key not found."},
        )

    client = AuthenticatedClient(**client_row)

    # ── Quota check ───────────────────────────────────────────
    if not client.is_pro and client.requests_this_month >= FREE_TIER_LIMIT:
        raise HTTPException(
            status_code=402,
            detail={
                "error":       "QUOTA_EXCEEDED",
                "message":     f"Free tier limit of {FREE_TIER_LIMIT} requests/month reached.",
                "upgrade_url": STRIPE_CHECKOUT_URL,
                "current_usage": client.requests_this_month,
                "limit":         FREE_TIER_LIMIT,
            },
        )

    # ── Atomic increment ──────────────────────────────────────
    try:
        supabase.rpc(
            "increment_request_count",
            {"client_id": client.id},
        ).execute()
    except Exception as exc:
        # Non-fatal — log and continue; don't block the user
        logger.warning("Counter increment failed for %s: %s", client.id, exc)

    return client


# ─────────────────────────────────────────────────────────────
#  SECTION 3 — DATA EXTRACTION ENGINES  (Lines 201 – 450)
# ─────────────────────────────────────────────────────────────

SCRAPE_HEADERS: Dict[str, str] = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en-IN,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Cache-Control":   "no-cache",
    "Pragma":          "no-cache",
}


def _clean_price(raw: str) -> Optional[float]:
    """Strip currency symbols and return float or None."""
    cleaned = re.sub(r"[^\d.]", "", raw.replace(",", ""))
    try:
        return float(cleaned) if cleaned else None
    except ValueError:
        return None


async def _fetch_html(url: str, client: httpx.AsyncClient) -> str:
    """Shared async HTTP fetch with retry logic."""
    for attempt in range(1, 4):
        try:
            response = await client.get(url, headers=SCRAPE_HEADERS, timeout=SCRAPE_TIMEOUT, follow_redirects=True)
            response.raise_for_status()
            return response.text
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code in (403, 404):
                raise  # No point retrying
            if attempt == 3:
                raise
            await asyncio.sleep(2 ** attempt)
        except httpx.RequestError:
            if attempt == 3:
                raise
            await asyncio.sleep(2 ** attempt)
    return ""  # Unreachable but satisfies type checker


async def scrape_amazon(url: str) -> Dict[str, Any]:
    """
    Extract product intelligence from an Amazon product page.
    Returns structured JSON with title, price, availability, rating,
    review count, ASIN, and image URL.
    """
    async with httpx.AsyncClient() as http:
        html = await _fetch_html(url, http)

    soup = BeautifulSoup(html, "html.parser")

    # ── Title ─────────────────────────────────────────────────
    title_tag = (
        soup.find("span", id="productTitle")
        or soup.find("h1", id="title")
    )
    title = title_tag.get_text(strip=True) if title_tag else None

    # ── Price ─────────────────────────────────────────────────
    price_whole = soup.find("span", class_="a-price-whole")
    price_frac  = soup.find("span", class_="a-price-fraction")
    price: Optional[float] = None
    if price_whole:
        raw = price_whole.get_text(strip=True)
        if price_frac:
            raw += price_frac.get_text(strip=True)
        price = _clean_price(raw)

    # Fallback: corePriceDisplay_desktop_feature_div
    if price is None:
        fallback = soup.find("span", class_="a-offscreen")
        if fallback:
            price = _clean_price(fallback.get_text(strip=True))

    # ── Availability ──────────────────────────────────────────
    avail_tag  = soup.find("div", id="availability")
    avail_text = avail_tag.get_text(strip=True) if avail_tag else ""
    in_stock   = bool(re.search(r"in stock", avail_text, re.IGNORECASE))

    # ── Rating ────────────────────────────────────────────────
    rating_tag = soup.find("span", class_="a-icon-alt")
    rating: Optional[float] = None
    if rating_tag:
        m = re.search(r"([\d.]+)\s*out", rating_tag.get_text())
        if m:
            rating = float(m.group(1))

    # ── Review count ──────────────────────────────────────────
    review_tag = soup.find("span", id="acrCustomerReviewText")
    review_count: Optional[int] = None
    if review_tag:
        m = re.search(r"([\d,]+)", review_tag.get_text())
        if m:
            review_count = int(m.group(1).replace(",", ""))

    # ── ASIN ──────────────────────────────────────────────────
    asin_tag = soup.find("input", id="ASIN")
    asin     = asin_tag["value"] if asin_tag else None

    # ── Image ─────────────────────────────────────────────────
    img_tag   = soup.find("img", id="landingImage") or soup.find("img", id="imgBlkFront")
    image_url = img_tag.get("src") or img_tag.get("data-old-hires") if img_tag else None

    return {
        "platform":     "amazon",
        "url":          url,
        "asin":         asin,
        "title":        title,
        "price":        price,
        "currency":     "INR",
        "in_stock":     in_stock,
        "availability": avail_text or None,
        "rating":       rating,
        "review_count": review_count,
        "image_url":    image_url,
        "scraped_at":   datetime.now(timezone.utc).isoformat(),
    }


async def scrape_meesho(url: str) -> Dict[str, Any]:
    """
    Extract product intelligence from a Meesho product page.
    Returns structured JSON with title, price, discount, seller info,
    and availability.
    """
    async with httpx.AsyncClient() as http:
        html = await _fetch_html(url, http)

    soup = BeautifulSoup(html, "html.parser")

    # ── Title ─────────────────────────────────────────────────
    title_tag = (
        soup.find("h1", class_=re.compile(r"product.*title|title.*product", re.I))
        or soup.find("span", class_=re.compile(r"ProductTitle", re.I))
        or soup.find("h1")
    )
    title = title_tag.get_text(strip=True) if title_tag else None

    # ── Selling price ─────────────────────────────────────────
    price_tag = (
        soup.find("h4", class_=re.compile(r"selling.*price|price", re.I))
        or soup.find("span", class_=re.compile(r"pdp-price|price", re.I))
    )
    price = _clean_price(price_tag.get_text(strip=True)) if price_tag else None

    # ── Original price / discount ─────────────────────────────
    original_tag = soup.find("span", class_=re.compile(r"strike|original.*price|mrp", re.I))
    original_price = _clean_price(original_tag.get_text(strip=True)) if original_tag else None

    discount_pct: Optional[float] = None
    if price and original_price and original_price > price:
        discount_pct = round((original_price - price) / original_price * 100, 1)

    # ── Availability ──────────────────────────────────────────
    oos_tag  = soup.find(string=re.compile(r"out of stock|sold out", re.I))
    in_stock = oos_tag is None

    # ── Delivery info ─────────────────────────────────────────
    delivery_tag = soup.find("p", class_=re.compile(r"delivery|ship", re.I))
    delivery_info = delivery_tag.get_text(strip=True) if delivery_tag else None

    # ── Image ─────────────────────────────────────────────────
    img_tag   = soup.find("img", class_=re.compile(r"product.*image|img.*product", re.I))
    image_url = img_tag.get("src") if img_tag else None

    return {
        "platform":       "meesho",
        "url":            url,
        "title":          title,
        "price":          price,
        "original_price": original_price,
        "discount_pct":   discount_pct,
        "currency":       "INR",
        "in_stock":       in_stock,
        "delivery_info":  delivery_info,
        "image_url":      image_url,
        "scraped_at":     datetime.now(timezone.utc).isoformat(),
    }


async def scrape_flipkart(url: str) -> Dict[str, Any]:
    """
    Extract product intelligence from a Flipkart product page.
    """
    async with httpx.AsyncClient() as http:
        html = await _fetch_html(url, http)

    soup = BeautifulSoup(html, "html.parser")

    title_tag = (
        soup.find("span", class_=re.compile(r"B_NuCI|title", re.I))
        or soup.find("h1", class_=re.compile(r"yhB1nd", re.I))
    )
    title = title_tag.get_text(strip=True) if title_tag else None

    price_tag = soup.find("div", class_=re.compile(r"_30jeq3|_16Jk6d", re.I))
    price     = _clean_price(price_tag.get_text(strip=True)) if price_tag else None

    mrp_tag       = soup.find("div", class_=re.compile(r"_3I9_wc", re.I))
    original_price = _clean_price(mrp_tag.get_text(strip=True)) if mrp_tag else None

    discount_tag = soup.find("div", class_=re.compile(r"_3Ay6Sb", re.I))
    discount_pct_raw = discount_tag.get_text(strip=True) if discount_tag else None

    oos_tag  = soup.find(class_=re.compile(r"_16FRp0", re.I))
    in_stock = oos_tag is None

    rating_tag = soup.find("div", class_=re.compile(r"_3LWZlK", re.I))
    rating: Optional[float] = None
    if rating_tag:
        try:
            rating = float(rating_tag.get_text(strip=True))
        except ValueError:
            pass

    return {
        "platform":       "flipkart",
        "url":            url,
        "title":          title,
        "price":          price,
        "original_price": original_price,
        "discount":       discount_pct_raw,
        "currency":       "INR",
        "in_stock":       in_stock,
        "rating":         rating,
        "scraped_at":     datetime.now(timezone.utc).isoformat(),
    }


# ─────────────────────────────────────────────────────────────
#  SHORTLINK RESOLUTION ENGINE
#
#  Amazon operates many regional shortlink / redirect domains.
#  All of them are HTTP 301/302 redirects to a canonical product
#  URL.  We follow the redirect chain (max 10 hops) and return the
#  resolved URL so the correct scraper receives a clean product URL.
#
#  Supported shortlink domains (exhaustive as of 2025-06):
#    amzn.to        – global mobile shortener (bit.ly-style)
#    amzn.in        – India-specific shortener
#    amzn.eu        – European shortener
#    amzn.com       – legacy US redirect domain
#    amzn.asia      – Asia-Pacific shortener
#    a.co           – ultra-short US redirect
#    z.cn           – Amazon China redirect
#    amazon.com/dp/<ASIN>?... (already canonical, just clean it)
#    Amazon affiliate deep-links (tag= param preserved but path cleaned)
# ─────────────────────────────────────────────────────────────

# Every known Amazon shortlink / redirect domain
AMAZON_SHORTLINK_DOMAINS: frozenset = frozenset([
    "amzn.to",
    "amzn.in",
    "amzn.eu",
    "amzn.com",
    "amzn.asia",
    "a.co",
    "z.cn",
    "amzn.me",    # Middle East
    "amzn.co.uk", # UK shortener variant
    "amzn.co.jp", # Japan shortener variant
])

# Full Amazon retail domains (all 20 regional storefronts)
AMAZON_RETAIL_DOMAINS: frozenset = frozenset([
    "amazon.com",
    "amazon.co.uk",
    "amazon.de",
    "amazon.fr",
    "amazon.it",
    "amazon.es",
    "amazon.co.jp",
    "amazon.in",
    "amazon.ca",
    "amazon.com.au",
    "amazon.com.br",
    "amazon.com.mx",
    "amazon.nl",
    "amazon.se",
    "amazon.pl",
    "amazon.sg",
    "amazon.ae",
    "amazon.sa",
    "amazon.eg",
    "amazon.com.tr",
    "amazon.cn",
])

# Query-string params that are safe to strip (tracking noise)
_STRIP_PARAMS: frozenset = frozenset([
    "ref", "ref_", "pf_rd_p", "pf_rd_r", "pf_rd_s", "pf_rd_t",
    "pf_rd_i", "pf_rd_m", "pd_rd_wg", "pd_rd_w", "pd_rd_r",
    "pd_rd_i", "dchild", "sprefix", "keywords", "crid", "qid",
    "sr", "s", "field-keywords", "linkId", "linkCode", "camp",
    "creative", "creativeASIN", "adId", "smid", "spLa",
    "cv_ct_cx", "maas",
])


def _extract_asin_from_url(url: str) -> Optional[str]:
    """
    Extract ASIN from any Amazon URL pattern:
      /dp/ASIN
      /gp/product/ASIN
      /gp/aw/d/ASIN
      /exec/obidos/ASIN/
      /o/ASIN/
      ?asin=ASIN
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
            # Basic ASIN sanity: 10 chars, alphanumeric, starts B or digit
            if re.fullmatch(r"[A-Z0-9]{10}", candidate):
                return candidate
    return None


def _canonicalize_amazon_url(url: str) -> str:
    """
    Given a fully-resolved Amazon URL, strip tracking noise and
    return a clean canonical /dp/<ASIN> URL on the same domain.
    Preserves the `tag` (affiliate) param if present.
    """
    parsed = urlparse(url)
    domain = parsed.netloc.lower().lstrip("www.")

    asin = _extract_asin_from_url(url)
    if asin:
        # Preserve affiliate tag if present
        qs = parse_qs(parsed.query)
        tag = qs.get("tag", [None])[0]
        query = f"tag={tag}" if tag else ""
        clean_path = f"/dp/{asin}"
        return urlunparse((parsed.scheme, parsed.netloc, clean_path, "", query, ""))

    # No ASIN found — strip junk params but keep the path
    qs = parse_qs(parsed.query, keep_blank_values=False)
    clean_qs = {k: v for k, v in qs.items() if k not in _STRIP_PARAMS}
    tag = qs.get("tag", [None])[0]
    if tag:
        clean_qs["tag"] = [tag]
    flat_qs = "&".join(f"{k}={v[0]}" for k, v in clean_qs.items())
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", flat_qs, ""))


def _domain_of(url: str) -> str:
    """Return bare domain (no www.) from a URL string."""
    try:
        return urlparse(url).netloc.lower().lstrip("www.")
    except Exception:
        return ""


def _is_amazon_shortlink(url: str) -> bool:
    domain = _domain_of(url)
    return any(domain == s or domain.endswith("." + s) for s in AMAZON_SHORTLINK_DOMAINS)


def _is_amazon_retail(url: str) -> bool:
    domain = _domain_of(url)
    return any(domain == s or domain.endswith("." + s) for s in AMAZON_RETAIL_DOMAINS)


async def resolve_url(raw_url: str) -> Tuple[str, str]:
    """
    Resolve any URL (including shortlinks) to its final destination.

    Returns:
        (resolved_url, platform_hint)

    Algorithm:
        1. If the URL is a known Amazon shortlink domain → follow redirects.
        2. If the resolved URL is an Amazon retail domain → canonicalize.
        3. Otherwise return as-is and detect platform from the final URL.

    Raises:
        HTTPException 422  – URL never resolves to a supported platform
        HTTPException 504  – Redirect chain timed out / network error
    """
    if not raw_url.startswith(("http://", "https://")):
        raw_url = "https://" + raw_url

    needs_resolution = _is_amazon_shortlink(raw_url)

    if needs_resolution:
        try:
            async with httpx.AsyncClient(
                follow_redirects=True,
                max_redirects=10,
                timeout=SCRAPE_TIMEOUT,
                headers=SCRAPE_HEADERS,
            ) as http:
                # HEAD first — cheaper; fall back to GET if server refuses HEAD
                try:
                    resp = await http.head(raw_url)
                except httpx.HTTPStatusError:
                    resp = await http.get(raw_url)
                resolved = str(resp.url)
        except httpx.TimeoutException:
            raise HTTPException(
                status_code=504,
                detail={
                    "error":   "SHORTLINK_TIMEOUT",
                    "message": f"Timed out resolving shortlink: {raw_url}",
                    "original_url": raw_url,
                },
            )
        except httpx.TooManyRedirects:
            raise HTTPException(
                status_code=422,
                detail={
                    "error":   "REDIRECT_LOOP",
                    "message": f"Redirect loop detected for: {raw_url}",
                    "original_url": raw_url,
                },
            )
        except httpx.RequestError as exc:
            raise HTTPException(
                status_code=504,
                detail={
                    "error":   "SHORTLINK_RESOLUTION_FAILED",
                    "message": str(exc),
                    "original_url": raw_url,
                },
            )
    else:
        resolved = raw_url

    # Canonicalize Amazon URLs
    if _is_amazon_retail(resolved):
        resolved = _canonicalize_amazon_url(resolved)

    platform = _detect_platform_from_resolved(resolved)
    return resolved, platform


def _detect_platform_from_resolved(url: str) -> str:
    """Route a fully-resolved URL to the correct scraper."""
    domain = _domain_of(url)
    if _is_amazon_retail(url) or _is_amazon_shortlink(url):
        return "amazon"
    if "meesho.com"   in domain: return "meesho"
    if "flipkart.com" in domain: return "flipkart"
    return "unknown"


def _detect_platform(url: str) -> str:
    """
    Legacy single-pass platform detector.
    For shortlinks, _detect_platform_from_resolved is used after resolution.
    Kept for backward compat with any internal callers.
    """
    if _is_amazon_shortlink(url) or _is_amazon_retail(url):
        return "amazon"
    domain = _domain_of(url)
    if "meesho.com"   in domain: return "meesho"
    if "flipkart.com" in domain: return "flipkart"
    return "unknown"


# ─────────────────────────────────────────────────────────────
#  SECTION 4 — PUBLIC API ENDPOINTS  (Lines 451 – 600)
# ─────────────────────────────────────────────────────────────

class PulseRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def must_be_supported_platform(cls, v: str) -> str:
        # Normalise — add scheme if missing so urlparse works
        normalised = v if v.startswith(("http://", "https://")) else "https://" + v
        domain = _domain_of(normalised)

        # Accept any known Amazon shortlink domain
        is_shortlink = any(
            domain == s or domain.endswith("." + s)
            for s in AMAZON_SHORTLINK_DOMAINS
        )
        # Accept any Amazon retail storefront
        is_retail = any(
            domain == s or domain.endswith("." + s)
            for s in AMAZON_RETAIL_DOMAINS
        )
        is_meesho   = "meesho.com"   in domain
        is_flipkart = "flipkart.com" in domain

        if not (is_shortlink or is_retail or is_meesho or is_flipkart):
            raise ValueError(
                "URL must be from a supported platform: Amazon (including shortlinks "
                "such as amzn.to, amzn.in, amzn.eu, a.co, amzn.asia, z.cn, amzn.me), "
                "Meesho, or Flipkart."
            )
        return v


@app.get("/", include_in_schema=False)
async def root():
    return {
        "service": "TitanFlow Data API",
        "status":  "operational",
        "version": "1.1.0",
        "docs":    "/docs",
    }


@app.get("/health", include_in_schema=False)
async def health():
    """Uptime check endpoint — no auth required."""
    return {"status": "ok", "ts": datetime.now(timezone.utc).isoformat()}


@app.post(
    "/v1/pulse",
    summary="Scrape a product URL",
    description=(
        "Pass any Amazon, Meesho, or Flipkart product URL. "
        "TitanFlow scrapes it in real time and returns structured product data."
    ),
    tags=["Data"],
)
@limiter.limit("60/minute")
async def pulse(
    request: Request,
    body: PulseRequest,
    client: AuthenticatedClient = Depends(verify_api_key),
):
    """
    **POST /v1/pulse**

    - Requires `X-Api-Key` header.
    - Free tier: 1 000 requests / month.
    - Pro tier: unlimited.
    - Accepts full product URLs **and** all Amazon shortlinks:
      `amzn.to`, `amzn.in`, `amzn.eu`, `amzn.com`, `amzn.asia`,
      `a.co`, `z.cn`, `amzn.me`, `amzn.co.uk`, `amzn.co.jp`.
      Shortlinks are transparently resolved and canonicalized before
      scraping; the `resolution` block in the response shows what
      happened.
    """
    start_ms     = time.monotonic()
    original_url = body.url

    # ── Step 1: Resolve shortlinks / canonicalize ─────────────
    try:
        resolved_url, platform = await resolve_url(original_url)
    except HTTPException:
        raise  # already formatted with proper detail

    was_shortlink = _is_amazon_shortlink(original_url)
    logger.info(
        "URL resolved | original=%s resolved=%s platform=%s shortlink=%s",
        original_url, resolved_url, platform, was_shortlink,
    )

    # ── Step 2: Scrape ────────────────────────────────────────
    try:
        if platform == "amazon":
            data = await scrape_amazon(resolved_url)
        elif platform == "meesho":
            data = await scrape_meesho(resolved_url)
        elif platform == "flipkart":
            data = await scrape_flipkart(resolved_url)
        else:
            raise HTTPException(
                status_code=422,
                detail={
                    "error":        "UNSUPPORTED_PLATFORM",
                    "message":      "Platform not supported.",
                    "resolved_url": resolved_url,
                },
            )
    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code
        if status == 403:
            raise HTTPException(
                status_code=503,
                detail={"error": "SCRAPE_BLOCKED", "message": "Target blocked the request. Retry."},
            )
        if status == 404:
            raise HTTPException(
                status_code=404,
                detail={"error": "PRODUCT_NOT_FOUND", "message": "Product page returned 404."},
            )
        raise HTTPException(
            status_code=502,
            detail={"error": "UPSTREAM_ERROR", "message": f"Target returned HTTP {status}."},
        )
    except httpx.RequestError as exc:
        logger.error("Network error scraping %s: %s", resolved_url, exc)
        raise HTTPException(
            status_code=504,
            detail={"error": "NETWORK_TIMEOUT", "message": "Request to target timed out."},
        )

    elapsed_ms = round((time.monotonic() - start_ms) * 1000)

    # ── Step 3: Build response ────────────────────────────────
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
        **({"resolution": resolution_meta} if resolution_meta else {}),
        "data":       data,
    }


@app.get(
    "/v1/account",
    summary="Get account usage",
    tags=["Account"],
)
async def account(client: AuthenticatedClient = Depends(verify_api_key)):
    """Return the authenticated client's quota and plan details."""
    remaining = (
        "unlimited"
        if client.is_pro
        else max(0, FREE_TIER_LIMIT - client.requests_this_month)
    )
    return {
        "email":              client.email,
        "plan":               "pro" if client.is_pro else "free",
        "requests_this_month": client.requests_this_month,
        "monthly_limit":      "unlimited" if client.is_pro else FREE_TIER_LIMIT,
        "requests_remaining": remaining,
        "upgrade_url":        None if client.is_pro else STRIPE_CHECKOUT_URL,
    }


# ─────────────────────────────────────────────────────────────
#  SECTION 5 — AUTOMATED BILLING WEBHOOK  (Lines 601 – 700)
# ─────────────────────────────────────────────────────────────

@app.post(
    "/webhook/stripe",
    include_in_schema=False,
)
async def stripe_webhook(request: Request, background_tasks: BackgroundTasks):
    """
    Stripe sends a signed payload here on every billing event.

    Handles:
      • `checkout.session.completed`  → upgrade client to Pro
      • `customer.subscription.deleted` → downgrade back to Free
    """
    payload     = await request.body()
    sig_header  = request.headers.get("stripe-signature", "")

    # ── Signature verification ────────────────────────────────
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
    except stripe.error.SignatureVerificationError:
        logger.warning("Invalid Stripe webhook signature.")
        raise HTTPException(status_code=400, detail="Invalid signature.")
    except Exception as exc:
        logger.error("Webhook parse error: %s", exc)
        raise HTTPException(status_code=400, detail="Webhook error.")

    event_type = event["type"]
    logger.info("Stripe event received: %s", event_type)

    if event_type == "checkout.session.completed":
        background_tasks.add_task(_handle_checkout_completed, event)

    elif event_type in (
        "customer.subscription.deleted",
        "customer.subscription.paused",
    ):
        background_tasks.add_task(_handle_subscription_cancelled, event)

    return {"received": True}


async def _handle_checkout_completed(event: Dict[str, Any]) -> None:
    """Upgrade client to Pro plan and reset their monthly counter."""
    session      = event["data"]["object"]
    customer_email = session.get("customer_email") or session.get("customer_details", {}).get("email")

    if not customer_email:
        logger.error("checkout.session.completed missing customer email: %s", session.get("id"))
        return

    try:
        supabase.table("clients").update(
            {"is_pro": True, "requests_this_month": 0}
        ).eq("email", customer_email).execute()
        logger.info("Upgraded %s to Pro.", customer_email)
    except Exception as exc:
        logger.error("Failed to upgrade %s: %s", customer_email, exc)


async def _handle_subscription_cancelled(event: Dict[str, Any]) -> None:
    """Downgrade client to Free plan when subscription lapses."""
    subscription   = event["data"]["object"]
    customer_id    = subscription.get("customer")

    if not customer_id:
        return

    try:
        stripe_customer = stripe.Customer.retrieve(customer_id)
        email           = stripe_customer.get("email")

        if email:
            supabase.table("clients").update(
                {"is_pro": False}
            ).eq("email", email).execute()
            logger.info("Downgraded %s to Free.", email)
    except Exception as exc:
        logger.error("Failed to downgrade customer %s: %s", customer_id, exc)


# ─────────────────────────────────────────────────────────────
#  SECTION 6 — ADMIN UTILITIES  (Lines 701 – 800)
# ─────────────────────────────────────────────────────────────

ADMIN_SECRET: str = os.environ.get("ADMIN_SECRET", "")


def require_admin(x_admin_secret: str = Header(...)) -> None:
    if not ADMIN_SECRET or x_admin_secret != ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="Forbidden.")


class CreateClientRequest(BaseModel):
    email: str


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

    try:
        result = (
            supabase.table("clients")
            .insert(
                {
                    "id":                   str(uuid.uuid4()),
                    "email":                body.email,
                    "api_key":              new_key,
                    "is_pro":               False,
                    "requests_this_month":  0,
                }
            )
            .execute()
        )
    except Exception as exc:
        logger.error("Client creation failed: %s", exc)
        raise HTTPException(
            status_code=500,
            detail={"error": "DB_ERROR", "message": "Could not create client."},
        )

    return {
        "message": "Client provisioned.",
        "email":   body.email,
        "api_key": new_key,
        "warning": "Save this key. It will not be shown again.",
    }


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
        raise HTTPException(
            status_code=500,
            detail={"error": "DB_ERROR", "message": str(exc)},
        )

    return {"message": f"Client {email} revoked."}


@app.post(
    "/admin/reset-quota/{email}",
    summary="Manually reset a client's monthly quota",
    tags=["Admin"],
    dependencies=[Depends(require_admin)],
)
async def reset_quota(email: str):
    """Force-reset a client's monthly request counter to 0."""
    try:
        supabase.table("clients").update(
            {"requests_this_month": 0}
        ).eq("email", email).execute()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    return {"message": f"Quota reset for {email}."}


# ─────────────────────────────────────────────────────────────
#  SECTION 7 — GLOBAL ERROR HANDLERS  (Lines 801 – 850)
# ─────────────────────────────────────────────────────────────

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    detail = exc.detail if isinstance(exc.detail, dict) else {"message": exc.detail}
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "status":  exc.status_code,
            **detail,
        },
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception on %s: %s", request.url.path, exc)
    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "error":   "INTERNAL_ERROR",
            "message": "An unexpected error occurred. Our team has been notified.",
        },
    )


# ─────────────────────────────────────────────────────────────
#  SECTION 8 — STARTUP / SHUTDOWN HOOKS  (Lines 851 – 900)
# ─────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup_event():
    logger.info("TitanFlow Data API v1.1.0 — starting up.")
    # Validate Supabase connectivity
    try:
        supabase.table("clients").select("id").limit(1).execute()
        logger.info("Supabase connection: OK")
    except Exception as exc:
        logger.critical("Supabase connection FAILED at startup: %s", exc)


@app.on_event("shutdown")
async def shutdown_event():
    logger.info("TitanFlow Data API — shutting down gracefully.")


# ─────────────────────────────────────────────────────────────
#  END OF FILE
# ─────────────────────────────────────────────────────────────
