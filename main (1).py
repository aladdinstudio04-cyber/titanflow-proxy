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
