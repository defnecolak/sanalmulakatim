from __future__ import annotations

import asyncio
import random
import base64
import hashlib
import hmac
import io
import json
import logging
import os
import platform
import ipaddress
import re
import sqlite3
import threading
import time
import uuid
import smtplib
from datetime import datetime, timedelta
from email.message import EmailMessage
from email.utils import formataddr
from collections import defaultdict, deque
from contextlib import contextmanager
from urllib.parse import urlparse, quote

from starlette.middleware.gzip import GZipMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, List, Optional, Tuple
from fastapi.responses import RedirectResponse

# PyMuPDF (fitz) — OCR/scan destekli PDF metin çıkarımı için.
# Bazı ortamlarda kurulum eksik olabiliyor; bu durumda uygulama tamamen çökmesin.
try:
    import fitz  # type: ignore  # PyMuPDF
except Exception:  # pragma: no cover
    fitz = None
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile, Response
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
try:
    from openai import OpenAI  # type: ignore
except Exception:  # pragma: no cover
    OpenAI = None  # type: ignore

# Optional DB: Postgres
try:
    import psycopg  # type: ignore
    from psycopg.rows import dict_row  # type: ignore
except Exception:  # pragma: no cover
    psycopg = None  # type: ignore
    dict_row = None  # type: ignore
from pydantic import BaseModel, Field
from pypdf import PdfReader
import requests  # type: ignore

# Extra security controls (WAF + ban list)
from security_controls import (
    WafBanConfig,
    BanDB,
    StrikeTracker,
    SecurityEventDB,
    waf_check,
    waf_should_read_body,
    body_limit_for_path,
    BodySizeLimitMiddleware,
)

# Backward compatible import (older zips used ban_key_from_request)
try:
    from security_controls import ban_key_for_request
except ImportError:  # pragma: no cover
    from security_controls import ban_key_from_request as ban_key_for_request


# Load env from backend/.env automatically
load_dotenv()

APP_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(APP_DIR, "static")
DATA_DIR = os.path.join(APP_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

# -----------------------------
# Logging / Observability
# -----------------------------

LOG_LEVEL = (os.getenv("LOG_LEVEL") or "INFO").upper().strip()
logger = logging.getLogger("app")
logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))

_fmt = logging.Formatter(
    fmt="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

if not logger.handlers:
    sh = logging.StreamHandler()
    sh.setFormatter(_fmt)
    logger.addHandler(sh)

    # File log (optional but useful on servers)
    try:
        fh = logging.FileHandler(os.path.join(DATA_DIR, "app.log"), encoding="utf-8")
        fh.setFormatter(_fmt)
        logger.addHandler(fh)
    except Exception:
        pass

# Optional Sentry
SENTRY_DSN = (os.getenv("SENTRY_DSN") or "").strip()
if SENTRY_DSN:
    try:
        import sentry_sdk  # type: ignore
        from sentry_sdk.integrations.asgi import SentryAsgiMiddleware  # type: ignore

        sentry_sdk.init(dsn=SENTRY_DSN, traces_sample_rate=0.0)
        logger.info("Sentry enabled.")
    except Exception as e:
        logger.warning(f"Sentry init failed: {type(e).__name__}: {e}")

# -----------------------------
# Helpers
# -----------------------------

def _read_env_raw(name: str) -> Optional[str]:
    """Read an environment variable, optionally from a *_FILE secret.

    If NAME is set and non-empty, returns it.
    Else if NAME_FILE is set to a file path, reads that file and returns its contents.

    This allows Docker/Kubernetes secrets without putting secrets into .env.
    """
    v = os.getenv(name)
    if v is not None and v.strip() != "":
        return v
    fp = (os.getenv(f"{name}_FILE") or "").strip()
    if fp:
        try:
            with open(fp, "r", encoding="utf-8") as f:
                return f.read().strip()
        except Exception:
            return None
    return None


def _env_float(name: str, default: float) -> float:
    raw = _read_env_raw(name)
    if raw is None:
        raw = str(default)
    try:
        return float((raw or "").strip())
    except Exception:
        return default


def _env_int(name: str, default: int) -> int:
    raw = _read_env_raw(name)
    if raw is None:
        raw = str(default)
    try:
        return int((raw or "").strip())
    except Exception:
        return default


def _env_str(name: str, default: str = "") -> str:
    raw = _read_env_raw(name)
    return (raw if raw is not None else default).strip()


def _env_bool(name: str, default: bool = False) -> bool:
    raw = _read_env_raw(name)
    if raw is None:
        return default
    v = (raw or "").strip().lower()
    if not v:
        return default
    return v in {"1", "true", "yes", "y", "on"}


def _is_tr(language: str) -> bool:

    """Best-effort check for Turkish language selections ("tr", "Türkçe", "Turkish")."""
    s = (language or "").strip().lower()
    return s.startswith("tr") or ("türk" in s) or ("turk" in s)

def _clean_text(s: str) -> str:
    return re.sub(r"[ \t]+\n", "\n", (s or "").strip())

def _safe_json_loads(s: str) -> Dict[str, Any]:
    try:
        return json.loads(s)
    except Exception:
        m = re.search(r"\{.*\}", s, flags=re.S)
        if not m:
            raise
        return json.loads(m.group(0))


# -----------------------------
# Security / Deployment defaults
# -----------------------------
DEBUG = _env_bool("DEBUG", False)
ENABLE_API_DOCS = _env_bool("ENABLE_API_DOCS", DEBUG)

# Only trust X-Forwarded-For / X-Real-IP headers when behind a trusted reverse proxy (Caddy/Nginx).
# In production: set TRUST_PROXY_HEADERS=1 and configure your proxy to set these headers.
TRUST_PROXY_HEADERS = _env_bool("TRUST_PROXY_HEADERS", DEBUG)

PUBLIC_BASE_URL = (_env_str("PUBLIC_BASE_URL", "http://localhost:5555") or "http://localhost:5555").rstrip("/")
APP_NAME = (_env_str("APP_NAME", "Sanal Mülakatım") or "Sanal Mülakatım").strip()

# Allowed browser Origins for POST requests (best-effort CSRF / drive-by abuse protection).
# If empty, derived from PUBLIC_BASE_URL.
_raw_origins = _env_str("ALLOWED_ORIGINS", "")
ALLOWED_ORIGINS = [o.strip().rstrip("/") for o in _raw_origins.split(",") if o.strip()]
if not ALLOWED_ORIGINS:
    try:
        p = urlparse(PUBLIC_BASE_URL)
        if p.scheme and p.netloc:
            ALLOWED_ORIGINS = [f"{p.scheme}://{p.netloc}"]
    except Exception:
        ALLOWED_ORIGINS = []

# Require Origin checks for browser POSTs (Origin header present). No Origin is allowed for
# server-to-server callbacks (e.g., iyzico payment callbacks).
REQUIRE_ORIGIN = _env_bool("REQUIRE_ORIGIN", not DEBUG)

# Backward-compatible: tests/ops may use ORIGIN_GUARD_ENABLED
ORIGIN_GUARD_ENABLED = _env_bool("ORIGIN_GUARD_ENABLED", REQUIRE_ORIGIN)

# Host header allowlist (prevents Host header attacks). Example:
# ALLOWED_HOSTS=sanalmulakatim.com,www.sanalmulakatim.com
_raw_hosts = _env_str("ALLOWED_HOSTS", "")
ALLOWED_HOSTS = [h.strip() for h in _raw_hosts.split(",") if h.strip()]

# Salt for anonymized client IDs (rate limiting & free plan counters).
# In production, set a stable random value: CLIENT_ID_SALT=...
CLIENT_ID_SALT = _env_str("CLIENT_ID_SALT", _env_str("SESSION_SECRET", "change-me-please"))

# Upload limits (defense against huge/malicious PDFs)
MAX_PDF_MB = _env_int("MAX_PDF_MB", 10)
MAX_PDF_PAGES = _env_int("MAX_PDF_PAGES", _env_int("PDF_MAX_PAGES", 25))

# Enable strict security headers (CSP, XFO, etc.)
SECURITY_HEADERS = _env_bool("SECURITY_HEADERS", True)
HSTS = _env_bool("HSTS", False)  # enable only when serving over HTTPS

# Optional: protect /api/health details behind an admin key header (x-admin-key).
ADMIN_STATUS_KEY = _env_str("ADMIN_STATUS_KEY", "")

# Admin API extra shared-secret header (set by reverse proxy like Caddy) for defence-in-depth.
# If set, /admin/* and /api/admin/* must include x-admin-edge-token header.
ADMIN_EDGE_TOKEN = _env_str("ADMIN_EDGE_TOKEN", "").strip()
# Optional second factor for admin API calls (in addition to x-admin-key). If set, requires x-admin-2fa header.
ADMIN_2FA_KEY = _env_str("ADMIN_2FA_KEY", "").strip()

# Extra defence-in-depth: optional IP allowlist for admin security panel routes
# (Still recommended to put these behind Caddy Basic Auth + IP allowlist.)
ADMIN_PANEL_ALLOW_IPS = _env_str("ADMIN_PANEL_ALLOW_IPS", "")

# CAPTCHA (optional)
# Protects email-triggering endpoints (e.g., Pro recovery link and delete confirmation link).
# Supported provider: turnstile (Cloudflare). If CAPTCHA_PROVIDER is empty, CAPTCHA is disabled.
CAPTCHA_PROVIDER = _env_str("CAPTCHA_PROVIDER", "").strip().lower()
TURNSTILE_SITE_KEY = _env_str("TURNSTILE_SITE_KEY", "")
TURNSTILE_SECRET_KEY = _env_str("TURNSTILE_SECRET_KEY", "")
CAPTCHA_TIMEOUT = _env_float("CAPTCHA_TIMEOUT", 5.0)
CAPTCHA_FAIL_OPEN = _env_bool("CAPTCHA_FAIL_OPEN", False)
CAPTCHA_REQUIRED_EMAIL = _env_bool("CAPTCHA_REQUIRED_EMAIL", True)
BAN_STRIKE_WEIGHT_CAPTCHA = _env_int("BAN_STRIKE_WEIGHT_CAPTCHA", 5)

# Automatic "lockdown" mode (anomaly / spike detection).
# When security events spike, we temporarily block expensive endpoints to keep the service alive.
LOCKDOWN_ENABLED = _env_bool("LOCKDOWN_ENABLED", True)
LOCKDOWN_WINDOW_SEC = _env_int("LOCKDOWN_WINDOW_SEC", 60)
LOCKDOWN_THRESHOLD_EVENTS = _env_int("LOCKDOWN_THRESHOLD_EVENTS", 120)
LOCKDOWN_THRESHOLD_SOURCES = _env_int("LOCKDOWN_THRESHOLD_SOURCES", 30)
LOCKDOWN_TTL_SEC = _env_int("LOCKDOWN_TTL_SEC", 300)
LOCKDOWN_CHECK_EVERY_SEC = _env_int("LOCKDOWN_CHECK_EVERY_SEC", 5)
LOCKDOWN_EVENT_TYPES = [
    x.strip() for x in (_env_str(
        "LOCKDOWN_EVENT_TYPES",
        "waf_trigger,ban_applied,rate_limit,captcha_fail,payload_too_large",
    ) or "").split(",")
    if x.strip()
]
# Comma-separated prefixes of endpoints to block while in lockdown.
LOCKDOWN_BLOCK_PREFIXES = [
    p.strip() for p in (_env_str(
        "LOCKDOWN_BLOCK_PREFIXES",
        "/api/evaluate,/api/start,/api/next,/api/transcribe,/api/parse_pdf,/api/billing/create_checkout,/api/billing/email_token,/api/pro/recovery,/api/privacy/delete",
    ) or "").split(",")
    if p.strip()
]

# Privacy-delete confirmation tokens
PRIVACY_DELETE_TOKEN_TTL_MIN = _env_int("PRIVACY_DELETE_TOKEN_TTL_MIN", 30)
# Debug helper: return token in API response (NEVER enable in production).
DEBUG_RETURN_PRIVACY_DELETE_TOKEN = _env_bool("DEBUG_RETURN_PRIVACY_DELETE_TOKEN", False)


def _request_ip(request: Request) -> str:
    """Best-effort client IP (supports x-forwarded-for)."""
    xff = (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
    if xff:
        return xff
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def _parse_ip_allowlist(value: str) -> list:
    nets: list = []
    for part in (value or "").split():
        part = part.strip()
        if not part:
            continue
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except Exception:
            # Ignore invalid entries
            continue
    return nets


_ADMIN_PANEL_ALLOWLIST = _parse_ip_allowlist(ADMIN_PANEL_ALLOW_IPS)


def require_admin_panel_ip(request: Request) -> None:
    """Extra defence-in-depth: return 404 if admin panel IP allowlist is set and IP is not allowed."""
    if not _ADMIN_PANEL_ALLOWLIST:
        return
    ip_str = _request_ip(request)
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except Exception:
        raise HTTPException(status_code=404, detail="not_found")
    for net in _ADMIN_PANEL_ALLOWLIST:
        if ip_obj in net:
            return
    raise HTTPException(status_code=404, detail="not_found")


def _captcha_enabled() -> bool:
    if CAPTCHA_PROVIDER == "turnstile":
        return bool(TURNSTILE_SECRET_KEY) and bool(TURNSTILE_SITE_KEY)
    return False


def _verify_turnstile(token: str, client_ip: str) -> bool:
    """Cloudflare Turnstile server-side verification."""
    try:
        r = requests.post(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data={
                "secret": TURNSTILE_SECRET_KEY,
                "response": token,
                "remoteip": client_ip,
            },
            timeout=CAPTCHA_TIMEOUT,
        )
        if r.status_code != 200:
            return False
        data = r.json() if r.content else {}
        return bool(data.get("success"))
    except Exception:
        return False


def require_captcha_or_raise(request: Request, captcha_token: Optional[str], *, purpose: str) -> None:
    """Raises 403 if CAPTCHA is enabled and verification fails.

    Security notes:
    - This is meant to protect *email-triggering* endpoints from automated abuse.
    - We record failures as security events (no raw IP stored; only ban_key/client_id hashes).
    """
    if not _captcha_enabled():
        return

    ip = _request_ip(request)

    def _record_fail(reason: str) -> None:
        # Best-effort only — never let logging break the request path.
        try:
            bk = ban_key_for_request(request, CLIENT_ID_SALT)
        except Exception:
            bk = None
        try:
            cid = None
            try:
                cid = get_client_ctx(request).client_id
            except Exception:
                cid = None

            # security events
            try:
                security_events.log(
                    "captcha_fail",
                    ban_key=bk,
                    client_id=cid,
                    method=request.method,
                    path=request.url.path,
                    status=403,
                    weight=BAN_STRIKE_WEIGHT_CAPTCHA,
                    ua=request.headers.get("user-agent", ""),
                    details={"purpose": purpose, "reason": reason},
                )
            except Exception:
                pass

            # strike + possible ban
            try:
                if strike_tracker and bk:
                    strike_tracker.add_strike(bk, weight=BAN_STRIKE_WEIGHT_CAPTCHA, reason="captcha_fail")
            except Exception:
                pass
        except Exception:
            pass

    if not captcha_token:
        _record_fail("missing")
        raise HTTPException(status_code=403, detail="captcha_gerekli")

    ok = False
    if CAPTCHA_PROVIDER == "turnstile":
        ok = _verify_turnstile(captcha_token, ip)

    if not ok:
        _record_fail("invalid")
        if CAPTCHA_FAIL_OPEN:
            return
        raise HTTPException(status_code=403, detail="captcha_gecersiz")


def _get_client() -> OpenAI:
    if OpenAI is None:
        raise HTTPException(status_code=500, detail="openai paketi bulunamadı. backend klasöründe: pip install -r requirements.txt")
    api_key = _env_str("OPENAI_API_KEY")
    if not api_key:
        raise HTTPException(status_code=400, detail="OPENAI_API_KEY eksik. backend/.env dosyana API key ekle.")
    timeout = _env_float("OPENAI_TIMEOUT", 90.0)
    try:
        return OpenAI(api_key=api_key, timeout=timeout)
    except TypeError:
        return OpenAI(api_key=api_key)

def _chat_json(
    client: OpenAI,
    *,
    model: str,
    messages: List[Dict[str, Any]],
    max_tokens: int,
) -> Dict[str, Any]:
    """
    Returns a JSON object. Uses response_format json_object when available.
    Falls back to plain text + parsing.
    """
    try:
        resp = client.chat.completions.create(
            model=model,
            messages=messages,
            response_format={"type": "json_object"},
            max_tokens=max_tokens,
        )
        content = resp.choices[0].message.content or "{}"
        return _safe_json_loads(content)
    except Exception:
        resp = client.chat.completions.create(
            model=model,
            messages=messages,
            max_tokens=max_tokens,
        )
        content = resp.choices[0].message.content or "{}"
        return _safe_json_loads(content)

def _ocr_images_with_openai(client: OpenAI, images_png: List[bytes], language: str) -> str:
    """
    OCR via OpenAI multimodal model (Responses API).
    Returns plain text.
    """
    model = (_env_str("OPENAI_OCR_MODEL") or _env_str("OPENAI_MODEL") or "gpt-4o-mini").strip()
    parts: List[Dict[str, Any]] = [
        {
            "type": "input_text",
            "text": (
                "Bu bir CV görüntüsü. Tüm metni eksiksiz çıkar ve düz metin (plain text) olarak döndür. "
                "Başlık/alt başlıkları koru, satırları makul şekilde böl."
            )
            if _is_tr(language)
            else "This is a resume image. Extract ALL text faithfully and return as plain text. Preserve headings reasonably."
        }
    ]
    for b in images_png:
        b64 = base64.b64encode(b).decode("utf-8")
        parts.append({"type": "input_image", "image_url": f"data:image/png;base64,{b64}"})

    try:
        r = client.responses.create(
            model=model,
            input=[{"role": "user", "content": parts}],
            max_output_tokens=2000,
        )
        text = getattr(r, "output_text", None)
        if isinstance(text, str) and text.strip():
            return text.strip()
        out = getattr(r, "output", []) or []
        acc = []
        for item in out:
            for c in getattr(item, "content", []) or []:
                t = getattr(c, "text", None)
                if isinstance(t, str):
                    acc.append(t)
        return "\n".join(acc).strip()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"OCR başarısız: {type(e).__name__}: {e}")

"""DB layer

This project started with SQLite (simple, zero-ops). For public launch, SQLite can be
totally fine *if you run a single instance*.

If you want:
- blue/green
- multiple app instances
- safer concurrency

…switch to Postgres by setting DATABASE_URL (or DB_ENGINE=postgres).

We keep the public interface (UsageDB methods) identical.
"""

# -----------------------------
# Usage / limits (SQLite or Postgres)
# -----------------------------

DB_PATH = _env_str("USAGE_DB_PATH", os.path.join(DATA_DIR, "usage.db"))

DB_ENGINE = (_env_str("DB_ENGINE", "") or "").strip().lower()
DATABASE_URL = (_env_str("DATABASE_URL", "") or "").strip()

# Convenience: if DB_ENGINE=postgres but DATABASE_URL isn't provided, build it from parts.
if (not DATABASE_URL) and DB_ENGINE == "postgres":
    pg_host = (_env_str("PG_HOST", "postgres") or "postgres").strip()
    pg_port = _env_int("PG_PORT", 5432)
    pg_user = (_env_str("PG_USER", "sanal") or "sanal").strip()
    pg_pass = (_env_str("PG_PASSWORD", "") or "").strip()
    pg_db = (_env_str("PG_DB", "sanal_mulakatim") or "sanal_mulakatim").strip()
    if pg_pass:
        DATABASE_URL = f"postgresql://{pg_user}:{quote(pg_pass)}@{pg_host}:{pg_port}/{pg_db}"
    else:
        DATABASE_URL = f"postgresql://{pg_user}@{pg_host}:{pg_port}/{pg_db}"


def _use_postgres() -> bool:
    u = (DATABASE_URL or "").strip().lower()
    if u.startswith("postgres://") or u.startswith("postgresql://"):
        return True
    return DB_ENGINE == "postgres"


class SQLiteUsageDB:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init()

    def _init(self) -> None:
        with self._lock:
            cur = self._conn.cursor()
            # Daily usage counters (kept for expensive ops like OCR)
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS usage_daily(
                  client_id TEXT NOT NULL,
                  day TEXT NOT NULL,
                  key TEXT NOT NULL,
                  count INTEGER NOT NULL DEFAULT 0,
                  PRIMARY KEY (client_id, day, key)
                );
                """
            )

            # Total usage counters (used for FREE "trial" limits that should NOT reset daily)
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS usage_total(
                  client_id TEXT NOT NULL,
                  key TEXT NOT NULL,
                  count INTEGER NOT NULL DEFAULT 0,
                  PRIMARY KEY (client_id, key)
                );
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS pro_tokens(
                  token TEXT PRIMARY KEY,
                  created_at INTEGER NOT NULL,
                  provider TEXT,
                  provider_ref TEXT,
                  stripe_session_id TEXT,
                  client_id TEXT
                );
                """
            )
            # Lightweight migration for older DBs
            cur.execute("PRAGMA table_info(pro_tokens);")
            cols = {r[1] for r in cur.fetchall()}
            if "provider" not in cols:
                cur.execute("ALTER TABLE pro_tokens ADD COLUMN provider TEXT;")
            if "provider_ref" not in cols:
                cur.execute("ALTER TABLE pro_tokens ADD COLUMN provider_ref TEXT;")

            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_pro_tokens_client ON pro_tokens(client_id);"
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_pro_tokens_ref ON pro_tokens(provider, provider_ref);"
            )

            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS payment_orders(
                  order_id TEXT PRIMARY KEY,
                  provider TEXT NOT NULL,
                  client_id TEXT,
                  email TEXT,
                  created_at INTEGER NOT NULL,
                  updated_at INTEGER,
                  status TEXT,
                  email_hash TEXT,
                  provider_token TEXT,
                  provider_payment_id TEXT,
                  last_error TEXT,
                  raw_response TEXT
                );
                """
            )

            # Migration: add missing columns for older DBs (SQLite supports ADD COLUMN)
            cur.execute("PRAGMA table_info(payment_orders);")
            pcols = {r[1] for r in cur.fetchall()}
            if "updated_at" not in pcols:
                cur.execute("ALTER TABLE payment_orders ADD COLUMN updated_at INTEGER;")
            if "status" not in pcols:
                cur.execute("ALTER TABLE payment_orders ADD COLUMN status TEXT;")
            if "email_hash" not in pcols:
                cur.execute("ALTER TABLE payment_orders ADD COLUMN email_hash TEXT;")
            if "provider_token" not in pcols:
                cur.execute("ALTER TABLE payment_orders ADD COLUMN provider_token TEXT;")
            if "provider_payment_id" not in pcols:
                cur.execute("ALTER TABLE payment_orders ADD COLUMN provider_payment_id TEXT;")
            if "last_error" not in pcols:
                cur.execute("ALTER TABLE payment_orders ADD COLUMN last_error TEXT;")
            if "raw_response" not in pcols:
                cur.execute("ALTER TABLE payment_orders ADD COLUMN raw_response TEXT;")

            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_payment_orders_client ON payment_orders(client_id);"
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_payment_orders_status ON payment_orders(status);"
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_payment_orders_email_hash ON payment_orders(email_hash);"
            )

            # Email ↔ token mapping (hashed email; supports recovery)
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS email_token_links(
                  email_hash TEXT NOT NULL,
                  token TEXT NOT NULL,
                  created_at INTEGER NOT NULL,
                  PRIMARY KEY (email_hash, token)
                );
                """
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_email_token_links_email ON email_token_links(email_hash);"
            )

            # One-time magic links for token recovery
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS recovery_links(
                  token_hash TEXT PRIMARY KEY,
                  email_hash TEXT NOT NULL,
                  created_at INTEGER NOT NULL,
                  expires_at INTEGER NOT NULL,
                  consumed_at INTEGER
                );
                """
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_recovery_links_email ON recovery_links(email_hash);"
            )

            # One-time magic links for privacy deletion confirmation
            # (We store only token_hash and email_hash; raw email is never persisted here.)
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS delete_links(
                  token_hash TEXT PRIMARY KEY,
                  email_hash TEXT NOT NULL,
                  created_at INTEGER NOT NULL,
                  expires_at INTEGER NOT NULL,
                  consumed_at INTEGER
                );
                """
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_delete_links_email ON delete_links(email_hash);"
            )
            self._conn.commit()

    @staticmethod
    def _now() -> int:
        return int(time.time())

    @staticmethod
    def _norm_email(email: str) -> str:
        return (email or "").strip().lower()

    def email_hash(self, email: str) -> str:
        """Hash email for storage/lookup.

        We avoid keeping raw emails in DB wherever possible.
        """
        norm = self._norm_email(email)
        salt = (_env_str("EMAIL_HASH_SALT") or "").strip()
        payload = (salt + "|" + norm).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    @staticmethod
    def _day() -> str:
        return time.strftime("%Y-%m-%d", time.localtime())

    def get_usage(self, client_id: str) -> Dict[str, int]:
        day = self._day()
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT key, count FROM usage_daily WHERE client_id=? AND day=?",
                (client_id, day),
            )
            rows = cur.fetchall()
        out = {r["key"]: int(r["count"]) for r in rows}
        return out

    def get_total_usage(self, client_id: str) -> Dict[str, int]:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT key, count FROM usage_total WHERE client_id=?",
                (client_id,),
            )
            rows = cur.fetchall()
        return {r["key"]: int(r["count"]) for r in rows}

    def inc(self, client_id: str, key: str, amount: int = 1) -> int:
        day = self._day()
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "INSERT INTO usage_daily(client_id, day, key, count) VALUES(?,?,?,?) "
                "ON CONFLICT(client_id, day, key) DO UPDATE SET count=count+excluded.count",
                (client_id, day, key, amount),
            )
            cur.execute(
                "SELECT count FROM usage_daily WHERE client_id=? AND day=? AND key=?",
                (client_id, day, key),
            )
            n = int(cur.fetchone()[0])
            self._conn.commit()
            return n

    def inc_total(self, client_id: str, key: str, amount: int = 1) -> int:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "INSERT INTO usage_total(client_id, key, count) VALUES(?,?,?) "
                "ON CONFLICT(client_id, key) DO UPDATE SET count=count+excluded.count",
                (client_id, key, amount),
            )
            cur.execute(
                "SELECT count FROM usage_total WHERE client_id=? AND key=?",
                (client_id, key),
            )
            n = int(cur.fetchone()[0])
            self._conn.commit()
            return n


    def add_pro_token(
        self,
        token: str,
        client_id: str | None,
        provider: str | None = None,
        provider_ref: str | None = None,
        stripe_session_id: str | None = None,
    ) -> None:
        now = int(time.time())
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "INSERT OR REPLACE INTO pro_tokens(token, created_at, provider, provider_ref, stripe_session_id, client_id) VALUES(?,?,?,?,?,?)",
                (token, now, provider, provider_ref, stripe_session_id, client_id),
            )
            self._conn.commit()

    def is_pro_token(self, token: str) -> bool:
        token = (token or "").strip()
        if not token:
            return False
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("SELECT token FROM pro_tokens WHERE token=? LIMIT 1", (token,))
            row = cur.fetchone()
        return row is not None

    def get_token_by_stripe_session(self, session_id: str) -> Optional[str]:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT token FROM pro_tokens WHERE stripe_session_id=? LIMIT 1",
                (session_id,),
            )
            row = cur.fetchone()
        if not row:
            return None
        return str(row["token"])


    def get_token_by_provider_ref(self, provider: str, ref: str) -> Optional[str]:
        provider = (provider or "").strip().lower()
        ref = (ref or "").strip()
        if not provider or not ref:
            return None
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT token FROM pro_tokens WHERE provider=? AND provider_ref=? LIMIT 1",
                (provider, ref),
            )
            row = cur.fetchone()
        if not row:
            return None
        return str(row["token"])

    def create_payment_order(self, order_id: str, provider: str, client_id: str | None, email: str | None) -> None:
        now = self._now()
        email_norm = self._norm_email(email or "") if email else None
        email_hash = self.email_hash(email_norm) if email_norm else None
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "INSERT OR REPLACE INTO payment_orders(order_id, provider, client_id, email, email_hash, created_at, updated_at, status) VALUES(?,?,?,?,?,?,?,?)",
                (
                    order_id,
                    (provider or "").strip().lower(),
                    client_id,
                    (email_norm if email_norm else None),
                    email_hash,
                    now,
                    now,
                    "INIT",
                ),
            )
            self._conn.commit()

    def update_payment_order(self, order_id: str, **fields: Any) -> None:
        """Update payment_orders with a dynamic set of fields.

        Always updates updated_at.
        """
        order_id = (order_id or "").strip()
        if not order_id:
            return

        allowed = {
            "client_id",
            "email",
            "email_hash",
            "status",
            "provider_token",
            "provider_payment_id",
            "last_error",
            "raw_response",
        }
        payload = {k: v for k, v in (fields or {}).items() if k in allowed}
        payload["updated_at"] = self._now()

        sets = ", ".join([f"{k}=?" for k in payload.keys()])
        vals = list(payload.values())
        vals.append(order_id)

        with self._lock:
            cur = self._conn.cursor()
            cur.execute(f"UPDATE payment_orders SET {sets} WHERE order_id=?", vals)
            self._conn.commit()

    def get_payment_order(self, order_id: str) -> Optional[Dict[str, Any]]:
        order_id = (order_id or "").strip()
        if not order_id:
            return None
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT order_id, provider, client_id, email, email_hash, created_at, updated_at, status, provider_token, provider_payment_id, last_error FROM payment_orders WHERE order_id=? LIMIT 1",
                (order_id,),
            )
            row = cur.fetchone()
        if not row:
            return None
        return dict(row)

    # -----------------------------
    # Email ↔ Token mapping (for Pro recovery)
    # -----------------------------

    def link_email_to_token(self, email: str, token: str) -> None:
        email = self._norm_email(email)
        token = (token or "").strip()
        if not email or not token:
            return
        h = self.email_hash(email)
        now = self._now()
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "INSERT OR IGNORE INTO email_token_links(email_hash, token, created_at) VALUES(?,?,?)",
                (h, token, now),
            )
            self._conn.commit()

    def get_tokens_for_email(self, email: str) -> List[str]:
        email = self._norm_email(email)
        if not email:
            return []
        h = self.email_hash(email)
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT token FROM email_token_links WHERE email_hash=? ORDER BY created_at DESC",
                (h,),
            )
            rows = cur.fetchall()
        out: List[str] = []
        for r in rows:
            t = str(r["token"]).strip()
            if t and t not in out:
                out.append(t)
        return out

    # -----------------------------
    # One-time recovery links
    # -----------------------------

    def _hash_recovery_token(self, raw: str) -> str:
        raw = (raw or "").strip()
        secret = (_env_str("RECOVERY_TOKEN_SECRET") or _env_str("SESSION_SECRET") or "").strip()
        payload = (secret + "|" + raw).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def create_recovery_link(self, email: str, ttl_minutes: int = 15) -> str:
        """Create a one-time magic link token for the email. Returns RAW token (send via email)."""
        email = self._norm_email(email)
        if not email:
            raise ValueError("email boş")

        raw = "ml_" + uuid.uuid4().hex + uuid.uuid4().hex[:8]
        token_hash = self._hash_recovery_token(raw)
        now = self._now()
        exp = now + max(5, int(ttl_minutes)) * 60
        eh = self.email_hash(email)

        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "INSERT OR REPLACE INTO recovery_links(token_hash, email_hash, created_at, expires_at, consumed_at) VALUES(?,?,?,?,NULL)",
                (token_hash, eh, now, exp),
            )
            self._conn.commit()
        return raw

    def consume_recovery_link(self, raw_token: str) -> Optional[str]:
        """Consume a magic link token. Returns email_hash if valid, else None."""
        raw_token = (raw_token or "").strip()
        if not raw_token:
            return None
        token_hash = self._hash_recovery_token(raw_token)
        now = self._now()
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT email_hash, expires_at, consumed_at FROM recovery_links WHERE token_hash=? LIMIT 1",
                (token_hash,),
            )
            row = cur.fetchone()
            if not row:
                return None
            exp = int(row["expires_at"])
            consumed = row["consumed_at"]
            if consumed is not None:
                return None
            if now > exp:
                return None

            cur.execute(
                "UPDATE recovery_links SET consumed_at=? WHERE token_hash=?",
                (now, token_hash),
            )
            self._conn.commit()
            return str(row["email_hash"])

    # -----------------------------
    # One-time privacy delete links
    # -----------------------------

    def _hash_delete_token(self, raw: str) -> str:
        raw = (raw or "").strip()
        secret = (_env_str("DELETE_TOKEN_SECRET") or _env_str("SESSION_SECRET") or "").strip()
        payload = (secret + "|" + raw).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def create_delete_link(self, email: str, ttl_minutes: int = 30) -> str:
        """Create a one-time delete confirmation token for the email. Returns RAW token (send via email)."""
        email = self._norm_email(email)
        if not email:
            raise ValueError("email boş")

        raw = "dl_" + uuid.uuid4().hex + uuid.uuid4().hex[:8]
        token_hash = self._hash_delete_token(raw)
        now = self._now()
        exp = now + max(5, int(ttl_minutes)) * 60
        eh = self.email_hash(email)

        with self._lock:
            cur = self._conn.cursor()
            # Invalidate previous pending delete tokens for the same email_hash
            cur.execute(
                "DELETE FROM delete_links WHERE email_hash=?",
                (eh,),
            )
            cur.execute(
                "INSERT OR REPLACE INTO delete_links(token_hash, email_hash, created_at, expires_at, consumed_at) VALUES(?,?,?,?,NULL)",
                (token_hash, eh, now, exp),
            )
            self._conn.commit()
        return raw

    def consume_delete_link(self, raw_token: str) -> Optional[str]:
        """Consume a delete confirmation token. Returns email_hash if valid, else None."""
        raw_token = (raw_token or "").strip()
        if not raw_token:
            return None
        token_hash = self._hash_delete_token(raw_token)
        now = self._now()
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT email_hash, expires_at, consumed_at FROM delete_links WHERE token_hash=? LIMIT 1",
                (token_hash,),
            )
            row = cur.fetchone()
            if not row:
                return None
            exp = int(row["expires_at"])
            consumed = row["consumed_at"]
            if consumed is not None:
                return None
            if now > exp:
                return None
            cur.execute(
                "UPDATE delete_links SET consumed_at=? WHERE token_hash=?",
                (now, token_hash),
            )
            self._conn.commit()
            return str(row["email_hash"])

    def get_tokens_by_email_hash(self, email_hash: str) -> List[str]:
        email_hash = (email_hash or "").strip()
        if not email_hash:
            return []
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT token FROM email_token_links WHERE email_hash=? ORDER BY created_at DESC",
                (email_hash,),
            )
            rows = cur.fetchall()
        out: List[str] = []
        for r in rows:
            t = str(r["token"]).strip()
            if t and t not in out:
                out.append(t)
        return out

    # -----------------------------
    # Privacy / retention
    # -----------------------------

    def email_has_any_data(self, email: str) -> bool:
        """Returns True if we have any email-linked records for this email.

        Used to avoid sending delete emails to completely unknown addresses.
        """
        email = self._norm_email(email)
        if not email:
            return False
        eh = self.email_hash(email)

        with self._lock:
            cur = self._conn.cursor()
            cur.execute("SELECT 1 FROM payment_orders WHERE email_hash=? LIMIT 1", (eh,))
            if cur.fetchone() is not None:
                return True
            cur.execute("SELECT 1 FROM email_token_links WHERE email_hash=? LIMIT 1", (eh,))
            if cur.fetchone() is not None:
                return True
            cur.execute("SELECT 1 FROM recovery_links WHERE email_hash=? LIMIT 1", (eh,))
            if cur.fetchone() is not None:
                return True
            return False

    def anonymize_email_hash(self, email_hash: str) -> Dict[str, int]:
        """Remove (anonymize) email-linked data for a given email hash.

        Keeps Pro tokens valid, but removes the ability to recover them via email.
        """
        if not email_hash:
            return {"payment_orders": 0, "email_links": 0, "recovery_links": 0, "delete_links": 0}

        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "UPDATE payment_orders SET email=NULL, email_hash=NULL WHERE email_hash=?",
                (email_hash,),
            )
            n_pay = cur.rowcount
            cur.execute("DELETE FROM email_token_links WHERE email_hash=?", (email_hash,))
            n_link = cur.rowcount
            cur.execute("DELETE FROM recovery_links WHERE email_hash=?", (email_hash,))
            n_rec = cur.rowcount
            cur.execute("DELETE FROM delete_links WHERE email_hash=?", (email_hash,))
            n_del = cur.rowcount
            self._conn.commit()

        return {
            "payment_orders": int(n_pay),
            "email_links": int(n_link),
            "recovery_links": int(n_rec),
            "delete_links": int(n_del),
        }

    def anonymize_email(self, email: str) -> Dict[str, int]:
        """Remove (anonymize) email-linked data for a given email.

        Keeps Pro tokens valid, but removes the ability to recover them via email.
        """
        email = self._norm_email(email)
        if not email:
            return {"payment_orders": 0, "email_links": 0, "recovery_links": 0, "delete_links": 0}
        eh = self.email_hash(email)
        return self.anonymize_email_hash(eh)

    def cleanup_retention(self, retention_days: int) -> None:
        """Best-effort cleanup of old data."""
        try:
            days = max(1, int(retention_days))
        except Exception:
            days = 90

        cutoff_ts = self._now() - days * 86400
        # usage_daily uses YYYY-MM-DD; build cutoff string
        cutoff_day = time.strftime("%Y-%m-%d", time.localtime(cutoff_ts))

        with self._lock:
            cur = self._conn.cursor()
            # Remove old usage counters
            cur.execute("DELETE FROM usage_daily WHERE day < ?", (cutoff_day,))
            # Remove old payment orders (no reason to keep forever in MVP)
            cur.execute("DELETE FROM payment_orders WHERE created_at < ?", (cutoff_ts,))
            # Remove expired/old recovery links
            cur.execute("DELETE FROM recovery_links WHERE expires_at < ?", (self._now(),))
            # Remove expired/old delete links
            cur.execute("DELETE FROM delete_links WHERE expires_at < ?", (self._now(),))
            # Keep email_token_links (hashed) unless user requests deletion
            self._conn.commit()

class PostgresUsageDB:
    """Postgres-backed implementation of the UsageDB API."""

    def __init__(self, url: str):
        if psycopg is None or dict_row is None:  # pragma: no cover
            raise RuntimeError("Postgres seçildi ama psycopg kurulu değil. requirements.txt -> psycopg[binary]")
        self.url = url
        self._lock = threading.Lock()
        self._conn = psycopg.connect(self.url, connect_timeout=8, row_factory=dict_row)
        self._init()

    def _init(self) -> None:
        with self._lock:
            with self._conn.cursor() as cur:
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS usage_daily(
                      client_id TEXT NOT NULL,
                      day TEXT NOT NULL,
                      key TEXT NOT NULL,
                      count INTEGER NOT NULL DEFAULT 0,
                      PRIMARY KEY (client_id, day, key)
                    );
                    """
                )
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS usage_total(
                      client_id TEXT NOT NULL,
                      key TEXT NOT NULL,
                      count INTEGER NOT NULL DEFAULT 0,
                      PRIMARY KEY (client_id, key)
                    );
                    """
                )
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS pro_tokens(
                      token TEXT PRIMARY KEY,
                      created_at BIGINT NOT NULL,
                      provider TEXT,
                      provider_ref TEXT,
                      stripe_session_id TEXT,
                      client_id TEXT
                    );
                    """
                )
                # Backward compatible: add columns if missing
                cur.execute("ALTER TABLE pro_tokens ADD COLUMN IF NOT EXISTS provider TEXT;")
                cur.execute("ALTER TABLE pro_tokens ADD COLUMN IF NOT EXISTS provider_ref TEXT;")

                cur.execute("CREATE INDEX IF NOT EXISTS idx_pro_tokens_client ON pro_tokens(client_id);")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_pro_tokens_ref ON pro_tokens(provider, provider_ref);")

                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS payment_orders(
                      order_id TEXT PRIMARY KEY,
                      provider TEXT NOT NULL,
                      client_id TEXT,
                      email TEXT,
                      created_at BIGINT NOT NULL,
                      updated_at BIGINT,
                      status TEXT,
                      email_hash TEXT,
                      provider_token TEXT,
                      provider_payment_id TEXT,
                      last_error TEXT,
                      raw_response TEXT
                    );
                    """
                )
                # Backward compatible columns
                cur.execute("ALTER TABLE payment_orders ADD COLUMN IF NOT EXISTS updated_at BIGINT;")
                cur.execute("ALTER TABLE payment_orders ADD COLUMN IF NOT EXISTS status TEXT;")
                cur.execute("ALTER TABLE payment_orders ADD COLUMN IF NOT EXISTS email_hash TEXT;")
                cur.execute("ALTER TABLE payment_orders ADD COLUMN IF NOT EXISTS provider_token TEXT;")
                cur.execute("ALTER TABLE payment_orders ADD COLUMN IF NOT EXISTS provider_payment_id TEXT;")
                cur.execute("ALTER TABLE payment_orders ADD COLUMN IF NOT EXISTS last_error TEXT;")
                cur.execute("ALTER TABLE payment_orders ADD COLUMN IF NOT EXISTS raw_response TEXT;")

                cur.execute("CREATE INDEX IF NOT EXISTS idx_payment_orders_client ON payment_orders(client_id);")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_payment_orders_status ON payment_orders(status);")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_payment_orders_email_hash ON payment_orders(email_hash);")

                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS email_token_links(
                      email_hash TEXT NOT NULL,
                      token TEXT NOT NULL,
                      created_at BIGINT NOT NULL,
                      PRIMARY KEY (email_hash, token)
                    );
                    """
                )
                cur.execute("CREATE INDEX IF NOT EXISTS idx_email_token_links_email ON email_token_links(email_hash);")

                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS recovery_links(
                      token_hash TEXT PRIMARY KEY,
                      email_hash TEXT NOT NULL,
                      created_at BIGINT NOT NULL,
                      expires_at BIGINT NOT NULL,
                      consumed_at BIGINT
                    );
                    """
                )
                cur.execute("CREATE INDEX IF NOT EXISTS idx_recovery_links_email ON recovery_links(email_hash);")

                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS delete_links(
                      token_hash TEXT PRIMARY KEY,
                      email_hash TEXT NOT NULL,
                      created_at BIGINT NOT NULL,
                      expires_at BIGINT NOT NULL,
                      consumed_at BIGINT
                    );
                    """
                )
                cur.execute("CREATE INDEX IF NOT EXISTS idx_delete_links_email ON delete_links(email_hash);")

            self._conn.commit()

    @staticmethod
    def _now() -> int:
        return int(time.time())

    @staticmethod
    def _norm_email(email: str) -> str:
        return (email or "").strip().lower()

    def email_hash(self, email: str) -> str:
        norm = self._norm_email(email)
        salt = (_env_str("EMAIL_HASH_SALT") or "").strip()
        payload = (salt + "|" + norm).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    @staticmethod
    def _day() -> str:
        return time.strftime("%Y-%m-%d", time.localtime())

    def get_usage(self, client_id: str) -> Dict[str, int]:
        day = self._day()
        with self._lock:
            with self._conn.cursor() as cur:
                cur.execute(
                    "SELECT key, count FROM usage_daily WHERE client_id=%s AND day=%s",
                    (client_id, day),
                )
                rows = cur.fetchall()
        return {r["key"]: int(r["count"]) for r in rows}

    def get_total_usage(self, client_id: str) -> Dict[str, int]:
        with self._lock:
            with self._conn.cursor() as cur:
                cur.execute(
                    "SELECT key, count FROM usage_total WHERE client_id=%s",
                    (client_id,),
                )
                rows = cur.fetchall()
        return {r["key"]: int(r["count"]) for r in rows}

    def inc(self, client_id: str, key: str, amount: int = 1) -> int:
        day = self._day()
        with self._lock:
            with self._conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO usage_daily(client_id, day, key, count)
                    VALUES(%s,%s,%s,%s)
                    ON CONFLICT(client_id, day, key)
                    DO UPDATE SET count = usage_daily.count + EXCLUDED.count
                    RETURNING count
                    """,
                    (client_id, day, key, int(amount)),
                )
                row = cur.fetchone()
            self._conn.commit()
        return int(row["count"] if row else 0)

    def inc_total(self, client_id: str, key: str, amount: int = 1) -> int:
        with self._lock:
            with self._conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO usage_total(client_id, key, count)
                    VALUES(%s,%s,%s)
                    ON CONFLICT(client_id, key)
                    DO UPDATE SET count = usage_total.count + EXCLUDED.count
                    RETURNING count
                    """,
                    (client_id, key, int(amount)),
                )
                row = cur.fetchone()
            self._conn.commit()
        return int(row["count"] if row else 0)

    def add_pro_token(
        self,
        token: str,
        client_id: str | None,
        provider: str | None = None,
        provider_ref: str | None = None,
        stripe_session_id: str | None = None,
    ) -> None:
        now = int(time.time())
        with self._lock:
            with self._conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO pro_tokens(token, created_at, provider, provider_ref, stripe_session_id, client_id)
                    VALUES(%s,%s,%s,%s,%s,%s)
                    ON CONFLICT(token) DO UPDATE SET
                      created_at=EXCLUDED.created_at,
                      provider=EXCLUDED.provider,
                      provider_ref=EXCLUDED.provider_ref,
                      stripe_session_id=EXCLUDED.stripe_session_id,
                      client_id=EXCLUDED.client_id
                    """,
                    (token, now, provider, provider_ref, stripe_session_id, client_id),
                )
            self._conn.commit()

    def is_pro_token(self, token: str) -> bool:
        token = (token or "").strip()
        if not token:
            return False
        with self._lock:
            with self._conn.cursor() as cur:
                cur.execute("SELECT 1 FROM pro_tokens WHERE token=%s LIMIT 1", (token,))
                row = cur.fetchone()
        return row is not None

    def get_token_by_stripe_session(self, session_id: str) -> Optional[str]:
        with self._lock:
            with self._conn.cursor() as cur:
                cur.execute(
                    "SELECT token FROM pro_tokens WHERE stripe_session_id=%s LIMIT 1",
                    (session_id,),
                )
                row = cur.fetchone()
        if not row:
            return None
        return str(row["token"]).strip()

    def get_token_by_provider_ref(self, provider: str, ref: str) -> Optional[str]:
        provider = (provider or "").strip().lower()
        ref = (ref or "").strip()
        if not provider or not ref:
            return None
        with self._lock:
            with self._conn.cursor() as cur:
                cur.execute(
                    "SELECT token FROM pro_tokens WHERE provider=%s AND provider_ref=%s LIMIT 1",
                    (provider, ref),
                )
                row = cur.fetchone()
        if not row:
            return None
        return str(row["token"]).strip()

    def create_payment_order(self, order_id: str, provider: str, client_id: str | None, email: str | None) -> None:
        now = self._now()
        email_norm = self._norm_email(email or "") if email else None
        email_hash = self.email_hash(email_norm) if email_norm else None
        with self._lock:
            with self._conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO payment_orders(order_id, provider, client_id, email, email_hash, created_at, updated_at, status)
                    VALUES(%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT(order_id) DO UPDATE SET
                      provider=EXCLUDED.provider,
                      client_id=EXCLUDED.client_id,
                      email=EXCLUDED.email,
                      email_hash=EXCLUDED.email_hash,
                      updated_at=EXCLUDED.updated_at,
                      status=EXCLUDED.status
                    """,
                    (
                        order_id,
                        (provider or "").strip().lower(),
                        client_id,
                        (email_norm if email_norm else None),
                        email_hash,
                        now,
                        now,
                        "INIT",
                    ),
                )
            self._conn.commit()

    def update_payment_order(self, order_id: str, **fields: Any) -> None:
        order_id = (order_id or "").strip()
        if not order_id:
            return

        allowed = {
            "client_id",
            "email",
            "email_hash",
            "status",
            "provider_token",
            "provider_payment_id",
            "last_error",
            "raw_response",
        }
        payload = {k: v for k, v in (fields or {}).items() if k in allowed}
        payload["updated_at"] = self._now()

        sets = ", ".join([f"{k}=%s" for k in payload.keys()])
        vals = list(payload.values())
        vals.append(order_id)

        with self._lock:
            with self._conn.cursor() as cur:
                cur.execute(f"UPDATE payment_orders SET {sets} WHERE order_id=%s", vals)
            self._conn.commit()

    def get_payment_order(self, order_id: str) -> Optional[Dict[str, Any]]:
        order_id = (order_id or "").strip()
        if not order_id:
            return None
        with self._lock:
            with self._conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT order_id, provider, client_id, email, email_hash, created_at, updated_at, status,
                           provider_token, provider_payment_id, last_error
                    FROM payment_orders
                    WHERE order_id=%s
                    LIMIT 1
                    """,
                    (order_id,),
                )
                row = cur.fetchone()
        if not row:
            return None
        return dict(row)

    def link_email_to_token(self, email: str, token: str) -> None:
        email = self._norm_email(email)
        token = (token or "").strip()
        if not email or not token:
            return
        h = self.email_hash(email)
        now = self._now()
        with self._lock:
            with self._conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO email_token_links(email_hash, token, created_at)
                    VALUES(%s,%s,%s)
                    ON CONFLICT(email_hash, token) DO NOTHING
                    """,
                    (h, token, now),
                )
            self._conn.commit()

    def get_tokens_for_email(self, email: str) -> List[str]:
        email = self._norm_email(email)
        if not email:
            return []
        h = self.email_hash(email)
        with self._lock:
            with self._conn.cursor() as cur:
                cur.execute(
                    "SELECT token FROM email_token_links WHERE email_hash=%s ORDER BY created_at DESC",
                    (h,),
                )
                rows = cur.fetchall()
        out: List[str] = []
        for r in rows:
            t = str(r["token"]).strip()
            if t and t not in out:
                out.append(t)
        return out

    def _hash_recovery_token(self, raw: str) -> str:
        raw = (raw or "").strip()
        secret = (_env_str("RECOVERY_TOKEN_SECRET") or _env_str("SESSION_SECRET") or "").strip()
        payload = (secret + "|" + raw).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def create_recovery_link(self, email: str, ttl_minutes: int = 15) -> str:
        email = self._norm_email(email)
        if not email:
            raise ValueError("email boş")

        raw = "ml_" + uuid.uuid4().hex + uuid.uuid4().hex[:8]
        token_hash = self._hash_recovery_token(raw)
        now = self._now()
        exp = now + max(5, int(ttl_minutes)) * 60
        eh = self.email_hash(email)

        with self._lock:
            with self._conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO recovery_links(token_hash, email_hash, created_at, expires_at, consumed_at)
                    VALUES(%s,%s,%s,%s,NULL)
                    ON CONFLICT(token_hash) DO UPDATE SET
                      email_hash=EXCLUDED.email_hash,
                      created_at=EXCLUDED.created_at,
                      expires_at=EXCLUDED.expires_at,
                      consumed_at=NULL
                    """,
                    (token_hash, eh, now, exp),
                )
            self._conn.commit()
        return raw

    def consume_recovery_link(self, raw_token: str) -> Optional[str]:
        raw_token = (raw_token or "").strip()
        if not raw_token:
            return None
        token_hash = self._hash_recovery_token(raw_token)
        now = self._now()
        with self._lock:
            with self._conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE recovery_links
                    SET consumed_at=%s
                    WHERE token_hash=%s
                      AND consumed_at IS NULL
                      AND expires_at >= %s
                    RETURNING email_hash
                    """,
                    (now, token_hash, now),
                )
                row = cur.fetchone()
            self._conn.commit()
        return str(row["email_hash"]) if row else None

    def _hash_delete_token(self, raw: str) -> str:
        raw = (raw or "").strip()
        secret = (_env_str("DELETE_TOKEN_SECRET") or _env_str("SESSION_SECRET") or "").strip()
        payload = (secret + "|" + raw).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def create_delete_link(self, email: str, ttl_minutes: int = 30) -> str:
        email = self._norm_email(email)
        if not email:
            raise ValueError("email boş")

        raw = "dl_" + uuid.uuid4().hex + uuid.uuid4().hex[:8]
        token_hash = self._hash_delete_token(raw)
        now = self._now()
        exp = now + max(5, int(ttl_minutes)) * 60
        eh = self.email_hash(email)

        with self._lock:
            with self._conn.cursor() as cur:
                # Invalidate previous pending delete tokens for this email
                cur.execute("DELETE FROM delete_links WHERE email_hash=%s", (eh,))
                cur.execute(
                    """
                    INSERT INTO delete_links(token_hash, email_hash, created_at, expires_at, consumed_at)
                    VALUES(%s,%s,%s,%s,NULL)
                    ON CONFLICT(token_hash) DO UPDATE SET
                      email_hash=EXCLUDED.email_hash,
                      created_at=EXCLUDED.created_at,
                      expires_at=EXCLUDED.expires_at,
                      consumed_at=NULL
                    """,
                    (token_hash, eh, now, exp),
                )
            self._conn.commit()
        return raw

    def consume_delete_link(self, raw_token: str) -> Optional[str]:
        raw_token = (raw_token or "").strip()
        if not raw_token:
            return None
        token_hash = self._hash_delete_token(raw_token)
        now = self._now()
        with self._lock:
            with self._conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE delete_links
                    SET consumed_at=%s
                    WHERE token_hash=%s
                      AND consumed_at IS NULL
                      AND expires_at >= %s
                    RETURNING email_hash
                    """,
                    (now, token_hash, now),
                )
                row = cur.fetchone()
            self._conn.commit()
        return str(row["email_hash"]) if row else None

    def get_tokens_by_email_hash(self, email_hash: str) -> List[str]:
        email_hash = (email_hash or "").strip()
        if not email_hash:
            return []
        with self._lock:
            with self._conn.cursor() as cur:
                cur.execute(
                    "SELECT token FROM email_token_links WHERE email_hash=%s ORDER BY created_at DESC",
                    (email_hash,),
                )
                rows = cur.fetchall()
        out: List[str] = []
        for r in rows:
            t = str(r["token"]).strip()
            if t and t not in out:
                out.append(t)
        return out

    def email_has_any_data(self, email: str) -> bool:
        email = self._norm_email(email)
        if not email:
            return False
        eh = self.email_hash(email)
        with self._lock:
            with self._conn.cursor() as cur:
                cur.execute("SELECT 1 FROM payment_orders WHERE email_hash=%s LIMIT 1", (eh,))
                if cur.fetchone() is not None:
                    return True
                cur.execute("SELECT 1 FROM email_token_links WHERE email_hash=%s LIMIT 1", (eh,))
                if cur.fetchone() is not None:
                    return True
                cur.execute("SELECT 1 FROM recovery_links WHERE email_hash=%s LIMIT 1", (eh,))
                if cur.fetchone() is not None:
                    return True
                return False

    def anonymize_email_hash(self, email_hash: str) -> Dict[str, int]:
        if not email_hash:
            return {"payment_orders": 0, "email_links": 0, "recovery_links": 0, "delete_links": 0}

        with self._lock:
            with self._conn.cursor() as cur:
                cur.execute(
                    "UPDATE payment_orders SET email=NULL, email_hash=NULL WHERE email_hash=%s",
                    (email_hash,),
                )
                n_pay = cur.rowcount
                cur.execute("DELETE FROM email_token_links WHERE email_hash=%s", (email_hash,))
                n_link = cur.rowcount
                cur.execute("DELETE FROM recovery_links WHERE email_hash=%s", (email_hash,))
                n_rec = cur.rowcount
                cur.execute("DELETE FROM delete_links WHERE email_hash=%s", (email_hash,))
                n_del = cur.rowcount
            self._conn.commit()

        return {
            "payment_orders": int(n_pay),
            "email_links": int(n_link),
            "recovery_links": int(n_rec),
            "delete_links": int(n_del),
        }

    def anonymize_email(self, email: str) -> Dict[str, int]:
        email = self._norm_email(email)
        if not email:
            return {"payment_orders": 0, "email_links": 0, "recovery_links": 0, "delete_links": 0}
        eh = self.email_hash(email)
        return self.anonymize_email_hash(eh)

    def cleanup_retention(self, retention_days: int) -> None:
        try:
            days = max(1, int(retention_days))
        except Exception:
            days = 90

        cutoff_ts = self._now() - days * 86400
        cutoff_day = time.strftime("%Y-%m-%d", time.localtime(cutoff_ts))

        with self._lock:
            with self._conn.cursor() as cur:
                cur.execute("DELETE FROM usage_daily WHERE day < %s", (cutoff_day,))
                cur.execute("DELETE FROM payment_orders WHERE created_at < %s", (cutoff_ts,))
                now = self._now()
                cur.execute("DELETE FROM recovery_links WHERE expires_at < %s", (now,))
                cur.execute("DELETE FROM delete_links WHERE expires_at < %s", (now,))
            self._conn.commit()


class UsageDB:
    """Facade that chooses SQLite vs Postgres based on env."""

    def __init__(self, sqlite_path: str):
        self.sqlite_path = sqlite_path
        self.engine = "postgres" if _use_postgres() else "sqlite"
        if self.engine == "postgres":
            self._impl = PostgresUsageDB(DATABASE_URL)
        else:
            self._impl = SQLiteUsageDB(sqlite_path)

    def __getattr__(self, name: str):
        return getattr(self._impl, name)


usage_db = UsageDB(DB_PATH)
try:
    logger.info(f"DB engine: {usage_db.engine}")
except Exception:
    pass

# WAF + ban list (app-level mini hardening)
wafban_cfg = WafBanConfig.from_env()
ban_db = BanDB(DB_PATH) if wafban_cfg.ban_enabled else None
strike_tracker = (
    StrikeTracker(cfg=wafban_cfg, ban_db=ban_db)
    if wafban_cfg.ban_enabled and ban_db is not None
    else None
)
security_events = SecurityEventDB(
    DB_PATH,
    retention_days=_env_int("SECURITY_EVENT_RETENTION_DAYS", 30),
)


# --- Automatic Lockdown (anomaly / spike response) ---------------------------

class LockdownManager:
    """Temporarily blocks expensive endpoints when attack traffic spikes.

    This is a pragmatic "keep the service alive" mode:
    - It does NOT try to be a full IDS.
    - It aims to reduce cost blow-ups (OCR/transcribe/model calls) during bot floods.
    - It triggers based on the security_events stream (WAF/rate_limit/ban/captcha).
    """

    def __init__(self, secdb: SecurityEventDB):
        self.secdb = secdb
        self.active_until: int = 0
        self.last_check: int = 0

        # Manual override (admin)
        self.forced_until: int = 0
        self.forced_reason: str = ""

    def _now(self) -> int:
        return int(time.time())

    def is_active(self) -> bool:
        now = self._now()
        return now < max(self.active_until, self.forced_until)

    def remaining_sec(self) -> int:
        now = self._now()
        return max(0, int(max(self.active_until, self.forced_until) - now))

    def status(self) -> dict:
        return {
            "enabled": bool(LOCKDOWN_ENABLED),
            "active": bool(self.is_active()),
            "remaining_sec": int(self.remaining_sec()),
            "active_until": int(max(self.active_until, self.forced_until)),
            "forced": bool(self.forced_until > self.active_until),
            "forced_reason": self.forced_reason,
            "cfg": {
                "window_sec": int(LOCKDOWN_WINDOW_SEC),
                "threshold_events": int(LOCKDOWN_THRESHOLD_EVENTS),
                "threshold_sources": int(LOCKDOWN_THRESHOLD_SOURCES),
                "ttl_sec": int(LOCKDOWN_TTL_SEC),
                "check_every_sec": int(LOCKDOWN_CHECK_EVERY_SEC),
                "event_types": list(LOCKDOWN_EVENT_TYPES),
                "block_prefixes": list(LOCKDOWN_BLOCK_PREFIXES),
            },
        }

    def deactivate(self, reason: str = "manual") -> None:
        self.active_until = 0
        self.forced_until = 0
        self.forced_reason = reason[:120]
        try:
            self.secdb.log("lockdown_deactivated", status=200, details={"reason": self.forced_reason})
        except Exception:
            pass

    def force(self, ttl_sec: int = 300, reason: str = "manual") -> None:
        now = self._now()
        ttl = max(30, int(ttl_sec))
        self.forced_until = now + ttl
        self.forced_reason = reason[:120]
        try:
            self.secdb.log(
                "lockdown_forced",
                status=503,
                details={"ttl_sec": ttl, "reason": self.forced_reason},
            )
        except Exception:
            pass

    def maybe_activate(self) -> None:
        if not LOCKDOWN_ENABLED:
            return

        now = self._now()
        if self.is_active():
            return

        if (now - self.last_check) < max(1, int(LOCKDOWN_CHECK_EVERY_SEC)):
            return

        self.last_check = now
        since_ts = now - max(5, int(LOCKDOWN_WINDOW_SEC))

        # Spike detection based on security event stream
        n_events = self.secdb.count_since(LOCKDOWN_EVENT_TYPES, since_ts)
        n_sources = self.secdb.count_distinct_ban_keys_since(LOCKDOWN_EVENT_TYPES, since_ts)

        if (n_events >= int(LOCKDOWN_THRESHOLD_EVENTS)) or (n_sources >= int(LOCKDOWN_THRESHOLD_SOURCES)):
            self.active_until = now + int(LOCKDOWN_TTL_SEC)
            try:
                self.secdb.log(
                    "lockdown_activated",
                    status=503,
                    details={
                        "window_sec": int(LOCKDOWN_WINDOW_SEC),
                        "events": int(n_events),
                        "sources": int(n_sources),
                        "threshold_events": int(LOCKDOWN_THRESHOLD_EVENTS),
                        "threshold_sources": int(LOCKDOWN_THRESHOLD_SOURCES),
                        "ttl_sec": int(LOCKDOWN_TTL_SEC),
                    },
                )
            except Exception:
                pass

    def should_block(self, request: Request) -> tuple[bool, int, str]:
        """Returns (block, retry_after_sec, reason)."""
        self.maybe_activate()
        if not self.is_active():
            return (False, 0, "")

        path = request.url.path or ""
        method = (request.method or "GET").upper()

        # Always allow static assets and health checks
        if path.startswith("/static/") or path in ("/api/healthz",):
            return (False, 0, "")

        if path.startswith("/api/health") or path.startswith("/api/public_config"):
            return (False, 0, "")

        # Always allow payment callbacks + redeem (avoid breaking successful purchases)
        if path.startswith("/api/billing/") and (
            "callback" in path or "webhook" in path or "redeem" in path
        ):
            return (False, 0, "")

        # Only block mutating calls (reduce cost blowups)
        if method not in ("POST", "PUT", "PATCH", "DELETE"):
            return (False, 0, "")

        # Block configured expensive prefixes
        if any(path.startswith(p) for p in LOCKDOWN_BLOCK_PREFIXES):
            retry = max(1, self.remaining_sec())
            return (True, int(retry), "lockdown")

        return (False, 0, "")


lockdown_mgr = LockdownManager(security_events)


# Manual pro tokens in env
_ENV_PRO_TOKENS = {t.strip() for t in (_env_str("PRO_TOKENS") or "").split(",") if t.strip()}

@dataclass
class ClientCtx:
    client_id: str
    is_pro: bool

def _get_ip(request: Request) -> str:
    # NOTE: Never trust proxy headers unless you are actually behind a trusted proxy.
    # Otherwise, attackers can spoof X-Forwarded-For to bypass rate limits.
    if TRUST_PROXY_HEADERS:
        xff = request.headers.get("x-forwarded-for")
        if xff:
            return xff.split(",")[0].strip()
        xri = request.headers.get("x-real-ip")
        if xri:
            return xri.strip()
    return request.client.host if request.client else "unknown"

def get_client_ctx(request: Request) -> ClientCtx:
    # Client ID is used only for abuse prevention (rate limits, free plan counters).
    # We anonymize the IP with a server-side salt so it is not stored as plain text.
    ip = _get_ip(request)
    salt = (CLIENT_ID_SALT or "").strip()
    cid = hashlib.sha256(f"{salt}|{ip}".encode("utf-8")).hexdigest()[:16]

    token = (request.headers.get("x-pro-token") or "").strip()
    is_pro = False
    if token:
        if token in _ENV_PRO_TOKENS or usage_db.is_pro_token(token):
            is_pro = True

    return ClientCtx(client_id=cid, is_pro=is_pro)

# In-memory rate limiting per minute (good enough for single-instance)
_rate_lock = threading.Lock()
_rate_hits: Dict[Tuple[str, str], Deque[float]] = defaultdict(deque)

def enforce_rate_limit(ctx: ClientCtx, key: str) -> None:
    """Endpoint-bazlı (key bazlı) rate limit.

    Amaç:
    - evaluate gibi maliyetli endpoint'leri daha sıkı sınırlamak
    - billing endpoint'lerini ayrı limit ile korumak
    - bot/abuse trafiklerini hızlıca 429 ile frenlemek

    Notlar:
    - Free/Pro için farklı limit tanımlayabilirsin.
    - Eski RATE_LIMIT_PER_MINUTE env'i hâlâ 'default' fallback olarak kullanılır.
    """
    # Pro kullanıcıları için tamamen bypass etmek istersen:
    if ctx.is_pro and _env_bool("PRO_BYPASS_RATE_LIMIT", True):
        return

    default_limit = _env_int("RATE_LIMIT_DEFAULT_PER_MIN", _env_int("RATE_LIMIT_PER_MINUTE", 60))
    default_window = float(_env_int("RATE_LIMIT_DEFAULT_WINDOW_SEC", 60))

    # Sensible per-endpoint defaults (env ile override edilebilir)
    per_key_defaults: dict[str, int] = {
        "billing": max(3, default_limit // 15),  # hassas endpoint: daha düşük
        "eval": max(10, default_limit // 3),     # maliyetli endpoint
        "transcribe": max(6, default_limit // 6),
        "parse_pdf": max(4, default_limit // 10),
        "start": max(6, default_limit // 6),
        "next": max(10, default_limit // 4),
        "privacy_delete_request": 3,
        "privacy_delete_confirm": 10,
        "recovery_request": 5,
        "email_token": 5,
    }

    ku = key.upper()
    free_limit = _env_int(f"RATE_LIMIT_{ku}_PER_MIN", per_key_defaults.get(key, default_limit))
    pro_limit = _env_int(f"RATE_LIMIT_{ku}_PER_MIN_PRO", max(free_limit * 10, free_limit))
    window = float(_env_int(f"RATE_LIMIT_{ku}_WINDOW_SEC", int(default_window)))

    limit = pro_limit if ctx.is_pro else free_limit
    if limit <= 0:
        return

    now = time.time()
    k = (ctx.client_id, key)
    with _rate_lock:
        dq = _rate_hits[k]
        while dq and dq[0] < now - window:
            dq.popleft()
        if len(dq) >= limit:
            # Retry-After: pencerenin dolmasını bekle
            reset_in = int(max(1, window - (now - dq[0]))) if dq else int(window)
            raise HTTPException(
                status_code=429,
                detail=f"Çok fazla istek (rate limit). {reset_in} sn sonra tekrar dene.",
                headers={
                    "Retry-After": str(reset_in),
                    # Bu header, middleware'de 'strike weight' vermek için kullanılıyor.
                    "X-SM-RateLimit": key,
                },
            )
        dq.append(now)


def enforce_daily_limit(ctx: ClientCtx, kind: str) -> None:
    if ctx.is_pro:
        return
    if kind == "eval":
        # FREE plan: total trial limit (does NOT reset daily)
        lim = _env_int("FREE_EVALS_TOTAL", 3)
        used = usage_db.get_total_usage(ctx.client_id).get("eval", 0)
        if lim > 0 and used >= lim:
            raise HTTPException(
                status_code=429,
                detail=f"Ücretsiz deneme hakkın bitti ({used}/{lim}). Pro’ya geç.",
            )
        return
    elif kind == "transcribe":
        lim = 0  # transcribe is included in FREE (no separate daily quota)
        key = "transcribe"
    elif kind == "ocr":
        lim = _env_int("FREE_OCR_PER_DAY", 2)
        key = "ocr"
    else:
        return
    if lim <= 0:
        return
    used = usage_db.get_usage(ctx.client_id).get(key, 0)
    if used >= lim:
        raise HTTPException(
            status_code=429,
            detail=f"Günlük limit doldu ({used}/{lim}). Yarın tekrar dene veya Pro’ya geç.",
        )

def charge_usage(ctx: ClientCtx, kind: str) -> None:
    if ctx.is_pro:
        return
    if kind == "eval":
        usage_db.inc_total(ctx.client_id, "eval", 1)
        return
    if kind in ["transcribe", "ocr"]:
        usage_db.inc(ctx.client_id, kind, 1)


# -----------------------------
# In-flight concurrency limits (defence-in-depth)
# -----------------------------
# Amaç: Aynı IP/istemciden (ve global olarak) çok fazla paralel "maliyetli" işlem başlatılmasını engellemek.
# Bu, bot saldırılarında hem CPU'yu hem de OpenAI maliyetlerini korur.
_INFLIGHT_LOCK = threading.Lock()
# (kind, client_id) -> (semaphore, last_seen_ts)
_INFLIGHT_PER_CLIENT: Dict[Tuple[str, str], Tuple[threading.BoundedSemaphore, float]] = {}
_INFLIGHT_TTL_SEC = _env_int("INFLIGHT_TTL_SEC", 3600)
_PRO_BYPASS_INFLIGHT = _env_bool("PRO_BYPASS_INFLIGHT", True)

def _prune_inflight(now: float | None = None) -> None:
    if _INFLIGHT_TTL_SEC <= 0:
        return
    now = float(time.time()) if now is None else float(now)
    with _INFLIGHT_LOCK:
        for k, (_sem, last_seen) in list(_INFLIGHT_PER_CLIENT.items()):
            if now - float(last_seen) > float(_INFLIGHT_TTL_SEC):
                _INFLIGHT_PER_CLIENT.pop(k, None)

def _make_global_sem(kind: str, default_n: int) -> Optional[threading.BoundedSemaphore]:
    n = _env_int(f"{kind.upper()}_MAX_INFLIGHT_GLOBAL", default_n)
    if n <= 0:
        return None
    return threading.BoundedSemaphore(n)

# Global concurrency caps (env ile override edilebilir)
_GLOBAL_INFLIGHT: Dict[str, Optional[threading.BoundedSemaphore]] = {
    "start": _make_global_sem("start", 6),
    "eval": _make_global_sem("eval", 6),
    "next": _make_global_sem("next", 6),
    "transcribe": _make_global_sem("transcribe", 3),
    "parse_pdf": _make_global_sem("parse_pdf", 2),
    "ocr": _make_global_sem("ocr", 2),
}

@contextmanager
def inflight(kind: str, ctx: ClientCtx):
    """Context manager: acquire per-client + global semaphores (non-blocking)."""
    kind = (kind or "").strip().lower() or "default"

    # PRO kullanıcıları için istersen bypass (env ile kapatılabilir)
    if ctx.is_pro and _PRO_BYPASS_INFLIGHT:
        yield
        return

    # Prune rarely to avoid memory growth
    if random.random() < 0.01:
        try:
            _prune_inflight()
        except Exception:
            pass

    per_lim = _env_int(f"{kind.upper()}_MAX_INFLIGHT_PER_CLIENT", 1)
    gsem = _GLOBAL_INFLIGHT.get(kind)

    acquired_g = False
    if gsem is not None:
        acquired_g = gsem.acquire(blocking=False)
        if not acquired_g:
            raise HTTPException(
                status_code=429,
                detail="Sunucu yoğun (paralel istek limiti). Lütfen bekleyip tekrar dene.",
                headers={"X-SM-RateLimit": f"{kind}_inflight"},
            )

    sem = None
    if per_lim > 0:
        key = (kind, ctx.client_id)
        now = float(time.time())
        with _INFLIGHT_LOCK:
            item = _INFLIGHT_PER_CLIENT.get(key)
            if item:
                sem = item[0]
            else:
                sem = threading.BoundedSemaphore(per_lim)
            _INFLIGHT_PER_CLIENT[key] = (sem, now)

        if sem is not None and (not sem.acquire(blocking=False)):
            # Release global if we held it
            if acquired_g and gsem is not None:
                try:
                    gsem.release()
                except Exception:
                    pass
            raise HTTPException(
                status_code=429,
                detail="Aynı anda çok fazla işlem başlattın. Lütfen tamamlanmasını bekle.",
                headers={"X-SM-RateLimit": f"{kind}_inflight"},
            )

    try:
        yield
    finally:
        if sem is not None:
            try:
                sem.release()
            except Exception:
                pass
        if acquired_g and gsem is not None:
            try:
                gsem.release()
            except Exception:
                pass


# -----------------------------
# Session store (in-memory)
# -----------------------------

@dataclass
class InterviewSession:
    id: str
    owner_client_id: str
    role: str
    seniority: str
    language: str
    n_questions: int
    created_at: float = field(default_factory=lambda: time.time())
    cv_text: str = ""
    questions: List[Dict[str, Any]] = field(default_factory=list)
    answers: List[Dict[str, Any]] = field(default_factory=list)
    current_index: int = 0
    last_focus: Optional[str] = None

SESSIONS: Dict[str, InterviewSession] = {}

def _cleanup_sessions() -> None:
    ttl_h = _env_float("SESSION_TTL_HOURS", 24.0)
    if ttl_h <= 0:
        return
    cutoff = time.time() - ttl_h * 3600.0
    stale = [sid for sid, s in SESSIONS.items() if s.created_at < cutoff]
    for sid in stale:
        SESSIONS.pop(sid, None)


# Session guardrails (DoS/cost protection)
MAX_SESSIONS_TOTAL = _env_int("MAX_SESSIONS_TOTAL", 2000)
MAX_ACTIVE_SESSIONS_PER_CLIENT = _env_int("MAX_ACTIVE_SESSIONS_PER_CLIENT", 3)

def _count_active_sessions_for_client(client_id: str) -> int:
    cid = (client_id or "").strip()
    if not cid:
        return 0
    n = 0
    for s in SESSIONS.values():
        if getattr(s, "owner_client_id", "") == cid:
            n += 1
    return n

def _enforce_session_limits(ctx: ClientCtx) -> None:
    """Defence-in-depth against memory/cost abuse via session spam."""
    try:
        _cleanup_sessions()
    except Exception:
        pass

    # Hard cap to avoid unbounded memory growth
    if MAX_SESSIONS_TOTAL > 0 and len(SESSIONS) >= MAX_SESSIONS_TOTAL:
        raise HTTPException(status_code=503, detail="Sunucu şu an yoğun. Lütfen biraz sonra tekrar dene.")

    # Per-client cap (reduces bot spam from a single source)
    if MAX_ACTIVE_SESSIONS_PER_CLIENT > 0:
        active = _count_active_sessions_for_client(ctx.client_id)
        if active >= MAX_ACTIVE_SESSIONS_PER_CLIENT:
            raise HTTPException(status_code=429, detail="Çok fazla aktif oturum var. Biraz bekleyip tekrar dene.")

def _role_lock_instruction(role: str) -> str:
    role_l = role.lower().strip()
    if any(k in role_l for k in ["doktor", "hekim", "acil", "tıp", "tip", "saglik", "sağlık"]):
        return (
            "Hedef rol SAĞLIK/HEKİMLİK. Siber güvenlik, yazılım, IT, bankacılık gibi alanlara KESİNLİKLE kayma. "
            "Sorular klinik iletişim, hasta güvenliği, ekip çalışması, triyaj, etik, temel klinik muhakeme ve süreç yönetimi etrafında olmalı."
        )
    if any(k in role_l for k in ["sekreter", "asistan", "yönetici", "yonetici"]):
        return (
            "Hedef rol SEKRETER/YÖNETİCİ ASİSTANI. Teknik/IT alanına kayma. Sorular önceliklendirme, iletişim, takvim, yazışma, gizlilik, çatışma yönetimi, düzen ve takip etrafında olmalı."
        )
    if any(k in role_l for k in ["siber", "cyber", "security", "güvenlik", "guvenlik"]):
        return (
            "Hedef rol SİBER GÜVENLİK. Sağlık/klinik senaryolarına kayma. Sorular olay müdahalesi, log analizi, risk, IAM, ağ güvenliği, SIEM, süreç ve iletişim etrafında olmalı."
        )
    return "Sorular hedef role sıkı şekilde bağlı kalmalı; CV farklı alansa sadece transfer edilebilir beceriler için kullan."

def _tokenize_for_similarity(s: str) -> List[str]:
    return re.findall(r"[a-zA-Z0-9ğüşöçıİĞÜŞÖÇ]+", (s or "").lower())

def _jaccard(a: List[str], b: List[str]) -> float:
    sa, sb = set(a), set(b)
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / float(len(sa | sb))

def _role_profile(role: str) -> Dict[str, Any]:
    r = (role or "").strip().lower()

    # Default profile (generic)
    profile: Dict[str, Any] = {
        "domain": "genel",
        "competencies": [
            "iletişim",
            "problem çözme",
            "önceliklendirme",
            "sorumluluk alma",
            "ekip çalışması",
            "geri bildirim alma/verme",
        ],
        "case_themes": ["zaman baskısı", "çatışma", "belirsizlik", "çoklu görev"],
        "keywords": [],
        "forbidden": [],
        "type_cycle_tr": ["davranışsal", "vaka", "teknik"],
        "type_cycle_en": ["behavioral", "case", "technical"],
    }

    if any(k in r for k in ["doktor", "hekim", "acil", "tıp", "tip", "saglik", "sağlık"]):
        profile.update({
            "domain": "sağlık/hekimlik",
            "competencies": [
                "hasta güvenliği",
                "triyaj ve önceliklendirme",
                "ekip içi iletişim ve devir teslim",
                "etik ve gizlilik",
                "stres altında karar verme",
                "temel klinik muhakeme (düşünce süreci)",
                "dokümantasyon",
                "hata yönetimi ve öğrenme",
            ],
            "case_themes": [
                "acil serviste dispne",
                "göğüs ağrısı",
                "sepsis şüphesi",
                "politravma",
                "ilaç/kimlik doğrulama hatası riski",
                "öfkeli hasta/ yakını",
                "yoğunlukta devir teslim",
            ],
            "keywords": ["hasta", "acil", "servis", "klinik", "triyaj", "güvenlik", "ekip", "devir", "etik", "gizlilik"],
            "forbidden": ["siber", "soc", "siem", "iam", "phishing", "ransomware", "firewall", "log", "network", "sql", "backend", "kubernetes"],
            "type_cycle_tr": ["davranışsal", "vaka", "vaka", "teknik"],
            "type_cycle_en": ["behavioral", "case", "case", "technical"],
        })
        return profile

    if any(k in r for k in ["sekreter", "asistan", "yönetici", "yonetici"]):
        profile.update({
            "domain": "sekreter/yönetici asistanı",
            "competencies": [
                "önceliklendirme",
                "takvim ve toplantı yönetimi",
                "yazışma ve net iletişim",
                "gizlilik ve profesyonellik",
                "paydaş yönetimi",
                "detay takibi",
                "kriz anında sakinlik",
            ],
            "case_themes": [
                "çakışan toplantılar",
                "son dakika seyahat değişikliği",
                "öncelik çatışması",
                "hassas belge/e-posta",
                "yoğun telefon trafiği",
                "zor bir paydaşla iletişim",
            ],
            "keywords": ["takvim", "toplantı", "mail", "yazış", "randevu", "öncelik", "gizlilik", "yönetici", "dosya"],
            "forbidden": ["siber", "soc", "siem", "iam", "phishing", "ransomware", "firewall", "log", "network", "kubernetes"],
            "type_cycle_tr": ["davranışsal", "vaka", "davranışsal", "vaka"],
            "type_cycle_en": ["behavioral", "case", "behavioral", "case"],
        })
        return profile

    if any(k in r for k in ["siber", "cyber", "security", "güvenlik", "guvenlik"]):
        profile.update({
            "domain": "siber güvenlik",
            "competencies": [
                "olay müdahalesi (incident response)",
                "log/telemetri analizi",
                "containment ve eradication",
                "risk değerlendirme",
                "iletişim ve raporlama",
                "IAM ve erişim kontrolleri",
                "süreç ve iyileştirme",
            ],
            "case_themes": [
                "phishing vakası",
                "ransomware şüphesi",
                "şüpheli oturum açma",
                "veri sızıntısı",
                "SIEM alarm triage",
                "kritik zafiyet yönetimi",
            ],
            "keywords": ["log", "siem", "alarm", "incident", "iam", "phishing", "ransomware", "erişim", "risk", "izleme"],
            "forbidden": ["hasta", "acil", "klinik", "triyaj", "tedavi", "muayene", "servis"],
            "type_cycle_tr": ["teknik", "vaka", "davranışsal", "vaka"],
            "type_cycle_en": ["technical", "case", "behavioral", "case"],
        })
        return profile

    return profile


def _experience_range_from_seniority(seniority: str, language: str) -> str:
    """
    Human-friendly experience range string derived from seniority.
    This is used for prompts and UI clarity; it is not a legal/official definition.
    """
    s = (seniority or "").strip().lower()
    tr = _is_tr(language)
    # Match the same buckets we show in the UI.
    if "yeni" in s or "mezun" in s or "junior" in s:
        return "0–1 yıl" if tr else "0–1 years"
    if "kıdem" in s or "kidem" in s or "senior" in s:
        return "5+ yıl" if tr else "5+ years"
    return "1–4 yıl" if tr else "1–4 years"


def _seniority_guidance(seniority: str, language: str) -> str:
    s = (seniority or "").strip().lower()
    tr = _is_tr(language)
    exp = _experience_range_from_seniority(seniority, language)

    if "yeni" in s or "mezun" in s or "junior" in s:
        return (
            f"Yeni mezun ({exp}) seviyesi: temel yaklaşım, öğrenme isteği, güvenli sınırlar, net iletişim. "
            "Aşırı ileri/stratejik beklenti koyma."
        ) if tr else (
            f"Junior ({exp}) level: fundamentals, learning mindset, safe boundaries, clear communication. "
            "Avoid overly strategic expectations."
        )

    if "kıdem" in s or "kidem" in s or "senior" in s:
        return (
            f"Kıdemli ({exp}) seviyesi: liderlik, eskalasyon, mentorluk, süreç iyileştirme, risk yönetimi, belirsizlikte yön verme."
        ) if tr else (
            f"Senior ({exp}) level: leadership, escalation, mentoring, process improvement, risk management, guiding in ambiguity."
        )

    return (
        f"Orta seviye ({exp}): bağımsız çalışma, önceliklendirme, paydaş yönetimi, uçtan uca sahiplenme, somut etki."
    ) if tr else (
        f"Mid ({exp}) level: independent execution, prioritization, stakeholder management, end-to-end ownership, measurable impact."
    )


def _choose_desired_type(role: str, language: str, asked_count: int) -> str:
    prof = _role_profile(role)
    cycle = prof["type_cycle_tr"] if _is_tr(language) else prof["type_cycle_en"]
    return cycle[asked_count % len(cycle)]

def _fill_followups(role: str, q_type: str, language: str) -> List[str]:
    tr = _is_tr(language)
    prof = _role_profile(role)

    # Role-aware defaults
    if str(prof.get("domain") or "").startswith("sağlık"):
        base = [
            "Bu durumda önceliklendirme kriterlerin ne olurdu?",
            "Ekip içi iletişimi ve eskalasyonu nasıl yönetirdin?",
            "Sonuç/etkiyi nasıl ölçer veya nasıl kapatırdın (öğrenim dâhil)?",
        ]
    elif str(prof.get("domain") or "").startswith("sekreter"):
        base = [
            "Bu durumda önceliklendirme kriterlerin ne olurdu?",
            "Yönetici ve paydaşlarla iletişimi nasıl kurardın?",
            "Sonuçta hangi çıktıyı hedeflerdin ve nasıl takip ederdin?",
        ]
    elif str(prof.get("domain") or "").startswith("siber"):
        base = [
            "Hangi telemetri/log kaynaklarına bakarak doğrulama yaparsın?",
            "İlk containment adımların neler olurdu ve neden?",
            "Sonrasında hangi aksiyonları (raporlama/iyileştirme) planlarsın?",
        ]
    else:
        base = [
            "Bu durumda önceliklendirmeyi nasıl yaparsın?",
            "İletişimi nasıl kurar ve netleştirirsin?",
            "Sonuç/etkiyi nasıl ölçer veya nasıl kapatırsın?",
        ]

    if not tr:
        base = [
            "What would your prioritization criteria be in this situation?",
            "How would you manage communication and escalation with stakeholders?",
            "How would you close the loop and measure impact/learning?",
        ]
        if str(prof.get("domain") or "").startswith("siber"):
            base = [
                "Which telemetry/log sources would you check to validate the incident?",
                "What are your first containment steps and why?",
                "What follow-up actions (reporting/improvement) would you plan?",
            ]

    # If technical type, slightly more technical followups
    qt = (q_type or "").lower()
    if tr and "tekn" in qt and str(prof.get("domain") or "").startswith("sağlık"):
        base[0] = "Hangi klinik verileri (örn. vitaller/lab) ve hangi karar eşiklerini takip edersin?"
    if tr and "tekn" in qt and str(prof.get("domain") or "").startswith("sekreter"):
        base[0] = "Hangi araç/süreçlerle (takvim, e-posta, doküman) hatasız ilerlersin?"
    if tr and "tekn" in qt and str(prof.get("domain") or "").startswith("siber"):
        base[0] = "Hangi log sorguları/hipotezlerle triage yaparsın (örnek yaklaşım)?"

    return base

def _validate_question_obj(role: str, language: str, q: Dict[str, Any], asked_so_far: List[str]) -> Tuple[bool, str]:
    prof = _role_profile(role)
    question = str(q.get("question") or "").strip()
    followups = q.get("followups") or []
    if not question or len(question.split()) < 6:
        return False, "Soru çok kısa/boş."
    if len(question) > 420:
        return False, "Soru çok uzun."
    # Duplicate / near-duplicate check
    tok_q = _tokenize_for_similarity(question)
    for prev in asked_so_far[-8:]:
        if not prev:
            continue
        sim = _jaccard(tok_q, _tokenize_for_similarity(prev))
        if sim >= 0.75:
            return False, "Soru önceki soruya çok benziyor."
    # Forbidden keywords check (hard guard)
    blob = (question + " " + " ".join([str(x) for x in followups])).lower()
    for bad in prof.get("forbidden") or []:
        if bad and bad.lower() in blob:
            return False, f"Hedef rolle uyumsuz içerik var ('{bad}')."
    return True, "OK"

def _generate_question(
    client: OpenAI,
    *,
    role: str,
    seniority: str,
    language: str,
    cv_text: str,
    asked_so_far: List[str],
    focus: Optional[str],
) -> Dict[str, Any]:
    model = (_env_str("OPENAI_MODEL") or "gpt-4o-mini").strip()
    max_tokens = _env_int("OPENAI_JSON_MAX_TOKENS", 1800)

    role_lock = _role_lock_instruction(role)
    prof = _role_profile(role)
    asked = "\n".join(f"- {q}" for q in asked_so_far[-8:]) if asked_so_far else "(yok)"
    desired_type = _choose_desired_type(role, language, len(asked_so_far))

    focus_text = ""
    if focus:
        focus_text = f"Bir önceki yanıta göre adayın geliştirmesi gereken alan: {focus}. Bir sonraki soruyu bunu geliştirecek şekilde seç."

    seniority_text = _seniority_guidance(seniority, language)
    exp_range = _experience_range_from_seniority(seniority, language)

    cv_hint = ""
    if cv_text:
        cv_hint = cv_text[:1800] + ("..." if len(cv_text) > 1800 else "")

    sys = (
        "Sen bir mülakat koçusun. Her zaman SADECE geçerli JSON döndürürsün. "
        "Asla Markdown kullanma, asla açıklama metni ekleme."
    )

    base_user = f"""
Hedef Rol: {role}
Kıdem: {seniority} ({exp_range})
Dil: {language}

KURALLAR (ÇOK ÖNEMLİ):
- {role_lock}
- {seniority_text}
- Bu sorunun türü: {desired_type}
- Soru GERÇEKÇİ olmalı ve işin günlük pratiğine uygun olmalı.
- Tek ana soru yaz (1–2 cümle). Gereksiz uzun paragraf yazma.
- 3 adet takip sorusu yaz; her biri farklı bir şeyi ölçsün (akıl yürütme, iletişim, etki/sonuç gibi).
- Daha önce sorulan sorularla çok benzer soru sorma.

İPUÇLARI (role referansı):
- Yetkinlikler: {", ".join(prof.get("competencies") or [])}
- Vaka temaları (örnek): {", ".join(prof.get("case_themes") or [])}

Daha önce sorulanlar:
{asked}

{focus_text}

CV (opsiyonel; SADECE transfer edilebilir beceri referansı):
{cv_hint}

İstenen JSON şeması:
{{
  "type": "davranışsal" | "teknik" | "vaka",
  "question": "tek ana soru",
  "followups": ["takip 1", "takip 2", "takip 3"]
}}

Not: Dil Türkçe ise type değerlerini Türkçe kullan (davranışsal/teknik/vaka)."""

    last_reason = ""
    q_obj: Dict[str, Any] = {}
    for attempt in range(3):
        user = base_user
        if attempt > 0:
            user += f"\n\nÖNCEKİ ÜRETİM GEÇERSİZ: {last_reason}. Yeni ve geçerli bir soru üret.\n"
        data = _chat_json(
            client,
            model=model,
            messages=[{"role": "system", "content": sys}, {"role": "user", "content": _clean_text(user)}],
            max_tokens=max_tokens,
        )

        q_type_raw = str((data.get("type") or "")).strip().lower()
        tr = _is_tr(language)
        if tr:
            if q_type_raw in ["behavioral", "davranissal", "davranışsal"]:
                q_type = "davranışsal"
            elif q_type_raw in ["technical", "teknik"]:
                q_type = "teknik"
            elif q_type_raw in ["case", "vaka"]:
                q_type = "vaka"
            else:
                q_type = desired_type if desired_type in ["davranışsal", "teknik", "vaka"] else "davranışsal"
        else:
            if q_type_raw in ["davranışsal", "davranissal", "behavioral"]:
                q_type = "behavioral"
            elif q_type_raw in ["teknik", "technical"]:
                q_type = "technical"
            elif q_type_raw in ["vaka", "case"]:
                q_type = "case"
            else:
                q_type = desired_type if desired_type in ["behavioral", "technical", "case"] else "behavioral"

        question = str(data.get("question") or "").strip()
        if question and not question.rstrip().endswith("?"):
            question = question.rstrip(".") + "?"

        followups = data.get("followups") or []
        if not isinstance(followups, list):
            followups = []
        followups = [str(x).strip() for x in followups if str(x).strip()]
        if len(followups) < 3:
            followups = (followups + _fill_followups(role, q_type, language))[:3]
        else:
            followups = followups[:3]
        followups = [fu if fu.endswith("?") else (fu.rstrip(".") + "?") for fu in followups]

        q_obj = {
            "id": str(uuid.uuid4()),
            "type": q_type,
            "question": question,
            "followups": followups,
        }

        ok, reason = _validate_question_obj(role, language, q_obj, asked_so_far)
        if ok:
            return q_obj
        last_reason = reason

    return q_obj

def _level_from_score(score: int, language: str) -> str:
    if _is_tr(language):
        if score < 40:
            return "Zayıf"
        if score < 70:
            return "Orta"
        return "Güçlü"
    else:
        if score < 40:
            return "Weak"
        if score < 70:
            return "Okay"
        return "Strong"

def _evaluate_answer(
    client: OpenAI,
    *,
    role: str,
    seniority: str,
    language: str,
    question: Dict[str, Any],
    answer: str,
) -> Dict[str, Any]:
    model = (_env_str("OPENAI_MODEL") or "gpt-4o-mini").strip()
    max_tokens = _env_int("OPENAI_JSON_MAX_TOKENS", 2500)

    sys = (
        "Sen bir mülakat koçusun. Her zaman SADECE geçerli JSON döndürürsün. "
        "Asla Markdown kullanma, asla açıklama metni ekleme."
    )

    star_line = "STAR (Durum, Görev, Eylem, Sonuç)"
    exp_range = _experience_range_from_seniority(seniority, language)
    user = f"""
Hedef Rol: {role}
Kıdem: {seniority} ({exp_range})
Dil: {language}

Soru Tipi: {question.get("type")}
Soru: {question.get("question")}
Takip: {question.get("followups")}

Aday Cevabı:
{answer}

GÖREV:
Aday cevabını değerlendir ve iyileştirmesi için detaylı ama okunabilir bir geri bildirim üret.
- {star_line} yapısını referans al.
- Cevap boş/çok kısa (≈30 kelimeden az) ya da taslak işaretleri ("...", boş madde, sadece şablon) içeriyorsa puan çok düşük olmalı.
  - Sadece iskelet/şablon varsa: overall_score = 0 ver.
  - Çok kısa ve somutluk yoksa: overall_score 0-15 aralığında kal.
- Tıbbi/klinik içerik varsa: eğitim amaçlı değerlendir; gerçek klinik karar yerine geçmez.
- top_fixes alanında mümkünse STAR'a hizalan:
  - P1: Durum + Görev (bağlam ve rolün netliği)
  - P2: Eylem (adımlar ve yaklaşım)
  - P3: Sonuç + Etki/Metrik (ölçülebilir sonuç)
- top_fixes[*].example alanı "kopyalanıp söylenebilir" olmalı:
  - 1. tekil şahısla yaz (örn. "Acil serviste ... yaptım"); üçüncü şahıs ("Bir hastanın...") kullanma.
  - "bahsederek/belirtmelisiniz" gibi yönerge dili kullanma; doğrudan örnek cümle yaz.
  - Soru bağlamına uygun en az 1 somut detay (nerede/kim/ne zaman) içersin.

DİL KURALI:
- Çıktıdaki TÜM alanlar Türkçe olmalı. İngilizce parantezli karşılıklar (Situation/Action/Result vb.) yazma.

İstenen JSON şeması:
{{
  "overall_score": 0-100,
  "level": "Zayıf/Orta/Güçlü",
  "one_sentence_goal": "Bir sonraki deneme için tek cümle hedef",
  "score_breakdown": {{
    "yapi_star": 0-20,
    "uygunluk": 0-20,
    "etki_metrik": 0-20,
    "netlik": 0-20,
    "ozguven": 0-20
  }},
  "summary": "2-3 cümlelik tek paragraf özet (liste yok, 1-5 numara yok). 1 cümle: ne iyi; 1-2 cümle: en büyük eksik ve nasıl düzeltilir.",
  "top_fixes": [
    {{
      "id": "P1",
      "title": "kısa başlık",
      "why": "neden önemli",
      "how": "nasıl düzeltilir",
      "example": "1-3 cümlelik örnek"
    }},
    {{ "id": "P2", "title": "...", "why": "...", "how": "...", "example": "..." }},
    {{ "id": "P3", "title": "...", "why": "...", "how": "...", "example": "..." }}
  ],
  "followup_question": "Tek takip sorusu",
  "example_answers": {{
    "short_30s": "30 saniyelik örnek cevap",
    "long_90s": "90 saniyelik örnek cevap"
  }},
  "red_flags": ["varsa 1-3 madde, yoksa boş liste"],
  "focus_area": "bir sonraki soru odağı (yapi_star/uygunluk/etki_metrik/netlik/ozguven)"
}}
"""
    data = _chat_json(
        client,
        model=model,
        messages=[{"role": "system", "content": sys}, {"role": "user", "content": _clean_text(user)}],
        max_tokens=max_tokens,
    )

    score = int(data.get("overall_score") or 0)
    score = max(0, min(100, score))
    data["overall_score"] = score
    data["level"] = data.get("level") or _level_from_score(score, language)

    bd = data.get("score_breakdown") or {}
    def _cap20(x: Any) -> int:
        try:
            v = int(x)
        except Exception:
            v = 0
        return max(0, min(20, v))

    data["score_breakdown"] = {
        "yapi_star": _cap20(bd.get("yapi_star")),
        "uygunluk": _cap20(bd.get("uygunluk")),
        "etki_metrik": _cap20(bd.get("etki_metrik")),
        "netlik": _cap20(bd.get("netlik")),
        "ozguven": _cap20(bd.get("ozguven")),
    }

    summary = str(data.get("summary") or "").strip()
    summary = re.sub(r"^\s*\d+\.\s+", "", summary, flags=re.M)
    data["summary"] = summary

    fixes = data.get("top_fixes") or []
    if not isinstance(fixes, list):
        fixes = []
    cleaned_fixes = []
    for i, fx in enumerate(fixes[:3]):
        if not isinstance(fx, dict):
            continue
        cleaned_fixes.append({
            "id": fx.get("id") or f"P{i+1}",
            "title": str(fx.get("title") or "").strip(),
            "why": str(fx.get("why") or "").strip(),
            "how": str(fx.get("how") or "").strip(),
            "example": str(fx.get("example") or "").strip(),
        })
    data["top_fixes"] = cleaned_fixes

    rf = data.get("red_flags") or []
    if not isinstance(rf, list):
        rf = []
    data["red_flags"] = [str(x).strip() for x in rf if str(x).strip()][:5]

    focus = str(data.get("focus_area") or "").strip()
    allowed_focus = {"yapi_star", "uygunluk", "etki_metrik", "netlik", "ozguven"}
    if focus not in allowed_focus:
        focus = "yapi_star"
    data["focus_area"] = focus

    # --- Guardrail: boş/taslak cevapları 0'a çek ---
    # Not: Model bazen çok kısa veya şablon cevaplara orta puan verebiliyor.
    def _looks_like_unfilled_template(text: str) -> bool:
        t = (text or "").strip()
        if not t:
            return True
        # Çok kısa içerik (tek kelime/tek cümle) => değerlendirme için yeterli değil
        words = re.findall(r"\w+", t, flags=re.UNICODE)
        if len(words) < 5:
            return True
        # Kullanıcı STAR iskeletini doldurmadan göndermişse
        if "..." in t:
            return True
        low = t.lower()
        hint_markers = [
            "star (durum, görev, eylem, sonuç)",
            "(kısa bağlam",  # STAR iskeletindeki ipuçları
            "(senin rolün",
            "adımlarını numaralandır",
            "metrik/etki (ölçülebilir)",
            "örnekler:",
        ]
        if any(m in low for m in hint_markers):
            return True

        # Ağırlıklı olarak başlık + boş madde ise
        lines = [ln.strip() for ln in t.splitlines() if ln.strip()]
        if lines:
            headings = {"durum:", "görev:", "eylem:", "sonuç:", "star (durum, görev, eylem, sonuç)"}
            boring = 0
            for ln in lines:
                l = ln.lower()
                if l in headings:
                    boring += 1
                elif l == "-" or l == "•" or re.fullmatch(r"-+", ln):
                    boring += 1
                elif ln.startswith("-") and len(ln) <= 3:
                    boring += 1
            if boring / max(1, len(lines)) >= 0.6 and len(words) < 40:
                return True
        return False

    if _looks_like_unfilled_template(answer):
        role_l = (role or "").lower()
        if any(k in role_l for k in ["doktor", "hekim", "tıp", "hemşire"]):
            ex_ctx = "Acil serviste nefes darlığı ile gelen bir hastada ilk değerlendirmeyi yaptığım bir an"
            ex_metric = "SpO2 84→92, solunum sayısı 30→20"
        elif any(k in role_l for k in ["sekreter", "asistan", "yönetici asistan", "idari"]):
            ex_ctx = "Yoğun bir günde aynı anda gelen acil toplantı, misafir karşılama ve evrak teslimi"
            ex_metric = "yanıt sürelerini %30 kısaltma / gecikmeyi sıfırlama"
        elif any(k in role_l for k in ["siber", "cyber", "security", "güvenlik"]):
            ex_ctx = "Şüpheli bir oturum açma dalgası tespit edip müdahale ettiğim bir olay"
            ex_metric = "hesap ele geçirme vakalarını 0'a indirme / MTTR'yi %40 azaltma"
        else:
            ex_ctx = "Teslim tarihi yaklaşan bir projede kritik bir riski yönettiğim bir durum"
            ex_metric = "teslimi 1 hafta öne çekme / hata oranını %15 azaltma"

        data["overall_score"] = 0
        data["score_breakdown"] = {
            "structure": 0,
            "relevance": 0,
            "impact": 0,
            "clarity": 0,
            "confidence": 0,
        }
        data["level"] = "Zayıf"
        data["focus_area"] = "yapi_star"
        data["summary"] = (
            "Cevap taslak/boş görünüyor; bu haliyle değerlendirme yapılacak yeterli içerik yok. "
            "Tek bir somut örnek seçip STAR (Durum–Görev–Eylem–Sonuç) formatında doldurman gerekiyor."
        )
        data["one_sentence_goal"] = "Tek bir somut örnek seç ve STAR (Durum–Görev–Eylem–Sonuç) şeklinde 60–90 saniyelik yanıt oluştur."
        data["top_fixes"] = [
            {
                "id": "P1",
                "title": "Somut bir örnek ve bağlam ver",
                "why": "Bağlam (Durum) ve rolün (Görev) net değilse, yaptıklarının anlamı ve doğru yaklaşım anlaşılamaz.",
                "how": f"{ex_ctx} gibi tek bir olayı seç. 1–2 cümlede nerede/ne zaman olduğunu, sorunun ne olduğunu ve senden beklenen görevi yaz.",
                "example": f"Durum: {ex_ctx}. Görev: İlk değerlendirme/koordinasyonu ben üstlendim.",
            },
            {
                "id": "P2",
                "title": "Eylemleri adım adım yaz",
                "why": "Eylem kısmı, profesyonel yaklaşımını ve karar mantığını gösterir.",
                "how": "2–4 madde ile neyi hangi sırayla yaptığını yaz (önceliklendirme, iletişim, kontrol listesi, eskalasyon vb.).",
                "example": "Eylem: (1) Hızlı önceliklendirme yaptım, (2) ilgili kişilere görev dağıttım, (3) kritik riski doğruladım ve takip planı koydum.",
            },
            {
                "id": "P3",
                "title": "Sonuç + ölçülebilir etki ekle",
                "why": "Sonuç, yaptıklarının işe yaradığını gösterir; metrik etkiyi somutlaştırır.",
                "how": f"Sonucu 1 cümlede yaz ve mümkünse 1 metrik ekle (örn. {ex_metric}). Ayrıca 1 öğrenim cümlesi ekle.",
                "example": f"Sonuç: Süreci stabilize ettik ve {ex_metric}. Öğrenim: Benzer durumda şu kontrol listesini standartlaştırdım.",
            },
        ]
        data["followup_question"] = "Bu soruya tek bir gerçek örnek üzerinden 60–90 saniyede STAR formatında yeniden cevap verebilir misin?"
        rf2 = list(data.get("red_flags") or [])
        rf2.append("Cevap taslak/boş; değerlendirme için yeterli içerik yok.")
        # dedupe + cap
        seen = set()
        cleaned = []
        for x in rf2:
            s = str(x).strip()
            if not s or s in seen:
                continue
            seen.add(s)
            cleaned.append(s)
        data["red_flags"] = cleaned[:5]

    return data

# -----------------------------
# FastAPI app + middleware
# -----------------------------

app = FastAPI(
    title="Sanal Mülakatım",
    docs_url="/docs" if ENABLE_API_DOCS else None,
    redoc_url="/redoc" if ENABLE_API_DOCS else None,
    openapi_url="/openapi.json" if ENABLE_API_DOCS else None,
)

# Enforce request body size limits even if Content-Length is missing/spoofed.
app.add_middleware(BodySizeLimitMiddleware, default_kb=_env_int("MAX_BODY_KB", 256))

# Middleware stack hardening
if ALLOWED_HOSTS:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS)
app.add_middleware(GZipMiddleware, minimum_size=800)

if SENTRY_DSN:
    try:
        from sentry_sdk.integrations.asgi import SentryAsgiMiddleware  # type: ignore
        app.add_middleware(SentryAsgiMiddleware)  # type: ignore
    except Exception:
        pass

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.on_event("startup")
async def _startup_cleanup() -> None:
    """Best-effort retention cleanup on startup.

    For a real production deployment, you'd run this as a scheduled job.
    """
    # Blue/green warmup or constrained environments may want to avoid *any* startup DB writes.
    if _env_bool("SKIP_STARTUP_CLEANUP", False):
        return
    try:
        usage_db.cleanup_retention(_env_int("DATA_RETENTION_DAYS", 90))
    except Exception as e:
        logger.warning(f"Retention cleanup failed: {type(e).__name__}: {e}")

def _origin_allowed(origin: str) -> bool:
    o = (origin or "").strip().rstrip("/")
    return (not o) or (o in ALLOWED_ORIGINS)



def _apply_security_headers(resp: Response, request: Request, rid: str) -> None:
    """Attach request-id and security headers.

    Must be called for both normal and early-return responses.
    """
    resp.headers["X-Request-ID"] = rid

    # Security headers (best-effort; you should also set these at the reverse proxy).
    if SECURITY_HEADERS:
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(self), geolocation=(), payment=()")
        resp.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        resp.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")

        # Content Security Policy (CSP):
        # - Default: scripts only from 'self'
        # - If CAPTCHA (Cloudflare Turnstile) is enabled, allow challenges.cloudflare.com for script + iframe.
        script_src = "'self'"
        frame_src = "'self'"
        connect_src = "'self'"
        needs_captcha_assets = request.url.path.startswith(("/delete", "/recover", "/api/privacy/delete", "/api/pro/recovery"))
        if _captcha_enabled() and needs_captcha_assets:
            script_src += " https://challenges.cloudflare.com"
            frame_src += " https://challenges.cloudflare.com"
            connect_src += " https://challenges.cloudflare.com"

        # NOTE: The app uses blob: URLs for in-browser audio preview (MediaRecorder).
        # Some browsers apply default-src to media if media-src isn't explicitly set.
        # We therefore whitelist blob: for media and workers.
        csp = (
            "default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; "
            f"script-src {script_src}; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; "
            f"connect-src {connect_src}; frame-src {frame_src}; media-src 'self' blob:; worker-src 'self' blob:"
        )
        resp.headers.setdefault("Content-Security-Policy", csp)

        if HSTS and (request.url.scheme == "https"):
            resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")

    # Cache hardening: never cache pages/endpoints that may contain tokens, admin data, or user-specific results.
    # This reduces accidental leakage via shared caches or back/forward cache.
    no_store_prefixes = (
        "/success",
        "/recover",
        "/delete",
        "/admin",
        "/api/admin",
        "/api/pro/recovery/consume",
        "/api/privacy/delete/confirm",
        "/api/billing/redeem",
    )
    if any(request.url.path.startswith(p) for p in no_store_prefixes):
        resp.headers.setdefault("Cache-Control", "no-store, max-age=0")
        resp.headers.setdefault("Pragma", "no-cache")

@app.middleware("http")
async def add_request_id_and_security(request: Request, call_next):
    rid = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    request.state.request_id = rid

    ua = request.headers.get("user-agent", "")
    try:
        client_id = get_client_ctx(request).client_id
    except Exception:
        client_id = None


    # Compute ban key (hashed IP) once.
    ban_key = None
    if wafban_cfg.waf_enabled or wafban_cfg.ban_enabled:
        ban_key = ban_key_for_request(request, CLIENT_ID_SALT)

    # 1) Ban check (mini fail2ban)
    if wafban_cfg.ban_enabled and ban_db and ban_key:
        try:
            if ban_db.is_banned(ban_key):
                security_events.log(
                    "ban_block",
                    ban_key=ban_key,
                    client_id=client_id,
                    method=request.method,
                    path=request.url.path,
                    status=403,
                    ua=ua,
                    details={"rid": rid},
                )
                resp = JSONResponse(
                    status_code=403,
                    content={
                        "detail": "Geçici olarak engellendiniz. Lütfen biraz sonra tekrar deneyin.",
                        "request_id": rid,
                    },
                )
                _apply_security_headers(resp, request, rid)
                return resp
        except Exception:
            # Never fail closed due to DB issues; log and keep serving.
            logger.exception("BanDB check failed")

    # 1.25) Automatic lockdown (spike response)
    # If we're under a bot flood / attack spike, temporarily block expensive endpoints
    # to keep the service alive and protect costs.
    try:
        block, retry_after, reason = lockdown_mgr.should_block(request)
        if block:
            security_events.log(
                "lockdown_block",
                ban_key=ban_key,
                client_id=client_id,
                method=request.method,
                path=request.url.path,
                status=503,
                ua=ua,
                details={"rid": rid, "retry_after": int(retry_after), "reason": reason},
            )
            resp = JSONResponse(
                status_code=503,
                content={
                    "detail": "Hizmet geçici olarak kısıtlandı (yoğunluk/güvenlik). Lütfen biraz sonra tekrar deneyin.",
                    "request_id": rid,
                },
            )
            resp.headers["Retry-After"] = str(int(max(1, retry_after)))
            _apply_security_headers(resp, request, rid)
            return resp
    except Exception:
        # Never fail closed because of lockdown manager errors
        pass

    # 1.5) Body size guard (cheap abuse protection)
    if request.method in ("POST", "PUT", "PATCH"):
        try:
            cl = request.headers.get("content-length")
            if cl and cl.isdigit():
                max_bytes = body_limit_for_path(request.url.path)
                if int(cl) > max_bytes:
                    security_events.log(
                        "payload_too_large",
                        ban_key=ban_key,
                        client_id=client_id,
                        method=request.method,
                        path=request.url.path,
                        status=413,
                        ua=ua,
                        details={"rid": rid, "content_length": int(cl), "max_bytes": int(max_bytes)},
                    )
                    # Treat as a WAF-ish strike to quickly stop bots uploading junk.
                    if wafban_cfg.ban_enabled and strike_tracker and ban_key:
                        strike_tracker.add_strike(
                            ban_key,
                            weight=wafban_cfg.ban_strike_weight_waf,
                            reason="payload_too_large",
                        )

                    resp = JSONResponse(
                        status_code=413,
                        content={"detail": "İstek çok büyük.", "request_id": rid},
                    )
                    _apply_security_headers(resp, request, rid)
                    return resp
        except Exception:
            # Don't ever take down the app over a defensive guardrail.
            pass

    # 2) Lightweight WAF (mainly blocks bot scans / obviously malicious inputs)
    if wafban_cfg.waf_enabled and ban_key:
        body_bytes = None
        if waf_should_read_body(request, wafban_cfg):
            try:
                body_bytes = await request.body()
            except Exception:
                body_bytes = None

        reasons = waf_check(request, body_bytes, wafban_cfg)
        if reasons:
            logger.warning(
                "WAF: rid=%s ipkey=%s path=%s reasons=%s",
                rid,
                ban_key,
                request.url.path,
                ",".join(reasons),
            )
            # Security log: WAF trigger
            security_events.log(
                "waf_trigger",
                ban_key=ban_key,
                client_id=client_id,
                method=request.method,
                path=request.url.path,
                status=403 if wafban_cfg.waf_block else 200,
                weight=wafban_cfg.ban_strike_weight_waf,
                ua=ua,
                details={"reasons": reasons},
            )

            # Strike + possible ban (weighted)
            if wafban_cfg.ban_enabled and strike_tracker:
                try:
                    tripped = strike_tracker.add_strike(ban_key, weight=wafban_cfg.ban_strike_weight_waf)
                    if tripped:
                        security_events.log(
                            "ban_applied",
                            ban_key=ban_key,
                            client_id=client_id,
                            method=request.method,
                            path=request.url.path,
                            status=403,
                            weight=wafban_cfg.ban_strike_weight_waf,
                            ua=ua,
                            details={"reason": "waf", "reasons": reasons},
                        )
                except Exception:
                    logger.exception("BanDB strike/ban failed")

            if wafban_cfg.waf_block:
                resp = JSONResponse(
                    status_code=403,
                    content={"detail": "İstek güvenlik nedeniyle engellendi.", "request_id": rid},
                )
                _apply_security_headers(resp, request, rid)
                return resp

    # 3) Origin guard (optional)
    if ORIGIN_GUARD_ENABLED and request.url.path.startswith("/api/"):
        origin = request.headers.get("origin")
        if origin and origin not in ALLOWED_ORIGINS:
            resp = JSONResponse(
                status_code=403,
                content={"detail": "forbidden_origin", "request_id": rid},
            )
            _apply_security_headers(resp, request, rid)
            return resp

    # 3.1) Sec-Fetch-Site guard (defence-in-depth):
    # Modern browsers send Sec-Fetch-Site for fetch/form requests. If we see a cross-site POST to /api,
    # we block it to reduce CSRF/drive-by abuse even when Origin is missing/misleading.
    if ORIGIN_GUARD_ENABLED and request.url.path.startswith("/api/") and request.method in ("POST", "PUT", "PATCH", "DELETE"):
        sfs = (request.headers.get("sec-fetch-site") or "").strip().lower()
        if sfs and sfs not in ("same-origin", "same-site"):
            resp = JSONResponse(
                status_code=403,
                content={"detail": "forbidden_fetch_site", "request_id": rid},
            )
            _apply_security_headers(resp, request, rid)
            return resp

    # 3.2) Progressive soft-delay (defence-in-depth):
    # If a client accumulates strikes (but isn't banned yet), add a small jittered delay.
    # This makes automated scanning/bruteforce slower without immediately banning.
    if wafban_cfg.ban_enabled and strike_tracker and ban_key:
        try:
            strikes = strike_tracker.get_strikes(ban_key)
            if strikes > 0:
                max_ms = _env_int("BAN_SOFT_DELAY_MS_MAX", 600)
                if max_ms > 0:
                    ratio = min(1.0, float(strikes) / float(max(1, wafban_cfg.ban_threshold)))
                    delay = (max_ms / 1000.0) * ratio * random.uniform(0.25, 1.0)
                    if delay >= 0.02:
                        await asyncio.sleep(delay)
        except Exception:
            pass

    resp = await call_next(request)
    # Ban on aggressive response patterns (weighted) for /api
    if (
        wafban_cfg.ban_enabled
        and strike_tracker
        and ban_key
        and request.url.path.startswith("/api")
        and resp.status_code in wafban_cfg.ban_strike_statuses
    ):
        try:
            rl_key = resp.headers.get("X-SM-RateLimit")
            if resp.status_code == 429 and rl_key:
                weight = wafban_cfg.ban_strike_weight_429
                event_type = "rate_limit"
                details = {"rate_limit_key": rl_key}
            else:
                weight = wafban_cfg.ban_strike_weight_default
                event_type = "strike_status"
                details = {}

            tripped = strike_tracker.add_strike(ban_key, weight=weight)

            d = dict(details)
            d["rid"] = rid
            security_events.log(
                event_type,
                ban_key=ban_key,
                client_id=client_id,
                method=request.method,
                path=request.url.path,
                status=resp.status_code,
                weight=weight,
                ua=ua,
                details=d,
            )

            if tripped:
                security_events.log(
                    "ban_applied",
                    ban_key=ban_key,
                    client_id=client_id,
                    method=request.method,
                    path=request.url.path,
                    status=resp.status_code,
                    weight=weight,
                    ua=ua,
                    details={"reason": "status", "status": resp.status_code, **details},
                )
        except Exception:
            logger.exception("BanDB strike/ban failed (status)")

    _apply_security_headers(resp, request, rid)
    return resp
# -----------------------------
# Pages
# -----------------------------

@app.get("/")
def landing():
    return FileResponse(os.path.join(STATIC_DIR, "landing.html"))

@app.get("/.well-known/security.txt")
def security_txt():
    # Public security contact (RFC 9116 style). Keep it short.
    body = """Contact: mailto:semi.ozgen@sanalmulakatim.com
Preferred-Languages: tr,en
Policy: https://sanalmulakatim.com/privacy
"""
    return Response(content=body, media_type="text/plain")

@app.get("/robots.txt")
def robots_txt():
    body = "User-agent: *\nDisallow: /api/\nDisallow: /admin/\nDisallow: /admin/security\nDisallow: /delete\nDisallow: /pro/recover\nDisallow: /success\nDisallow: /cancel\n"
    return Response(content=body, media_type="text/plain")


@app.get("/app")
def app_page():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))

@app.get("/privacy")
def privacy_page():
    return FileResponse(os.path.join(STATIC_DIR, "privacy.html"))

@app.get("/terms")
def terms_page():
    return FileResponse(os.path.join(STATIC_DIR, "terms.html"))

@app.get("/refund")
def refund_page():
    return FileResponse(os.path.join(STATIC_DIR, "refund.html"))

@app.get("/contact")
def contact_page():
    return FileResponse(os.path.join(STATIC_DIR, "contact.html"))

@app.get("/recover")
def recover_page():
    return FileResponse(os.path.join(STATIC_DIR, "recover.html"))

@app.get("/delete")
def delete_page():
    return FileResponse(os.path.join(STATIC_DIR, "delete.html"))

@app.get("/success")
def success_page():
    return FileResponse(os.path.join(STATIC_DIR, "success.html"))

@app.get("/cancel")
def cancel_page():
    return FileResponse(os.path.join(STATIC_DIR, "cancel.html"))

# -----------------------------
# API
# -----------------------------

@app.get("/api/healthz")
def healthz():
    return {"ok": True}


@app.get("/api/health")
def health(request: Request):
    # Optional hardening: hide detailed config unless the admin key is provided.
    if ADMIN_STATUS_KEY:
        sent = (request.headers.get("x-admin-key") or "").strip()
        if not hmac.compare_digest(sent, ADMIN_STATUS_KEY):
            return {"ok": True}

    key_ok = bool(_env_str("OPENAI_API_KEY"))
    stripe_ok = _stripe_enabled()
    iyzico_ok = _iyzico_enabled()
    provider = _payment_provider()
    return {
        "ok": True,
        "openai_key": key_ok,
        "model": (_env_str("OPENAI_MODEL") or "gpt-4o-mini"),
        "payment_provider": provider,
        "stripe_configured": stripe_ok,
        "iyzico_configured": iyzico_ok,
        "limits": {
            # FREE evals are TOTAL trials (not daily)
            "free_evals_total": _env_int("FREE_EVALS_TOTAL", 3),
            "free_transcribes_per_day": _env_int("FREE_TRANSCRIBES_PER_DAY", 0),
            "free_ocr_per_day": _env_int("FREE_OCR_PER_DAY", 2),
            "rate_limit_per_minute": _env_int("RATE_LIMIT_PER_MINUTE", 60),
        }
    }


@app.get("/api/public_config")
def public_config():
    """Public, non-sensitive config for static pages."""
    provider = _payment_provider()
    retention_days = _env_int("DATA_RETENTION_DAYS", 90)
    return {
        "app_name": (_env_str("APP_NAME") or "Sanal Mülakatım"),
        "support_email": (_env_str("SUPPORT_EMAIL") or "semi.ozgen@sanalmulakatim.com"),
        "public_base_url": (_env_str("PUBLIC_BASE_URL") or "http://localhost:5555").rstrip("/"),
        "payment_provider": provider,
        "smtp_configured": _smtp_enabled(),
        "stripe_configured": _stripe_enabled(),
        "iyzico_configured": _iyzico_enabled(),
        "data_retention_days": int(retention_days),
        "captcha": {
            "enabled": bool(_captcha_enabled()),
            "provider": (CAPTCHA_PROVIDER if _captcha_enabled() else ""),
            "site_key": (TURNSTILE_SITE_KEY if _captcha_enabled() else ""),
        },
    }



def _require_admin(request: Request):
    # Defence-in-depth:
    # 1) Optional IP allowlist (backend-level, independent from Caddy)
    require_admin_panel_ip(request)

    # 2) Optional edge-shared secret header (should be injected by reverse proxy)
    if ADMIN_EDGE_TOKEN:
        edge = (request.headers.get("x-admin-edge-token") or "").strip()
        if not edge or not hmac.compare_digest(edge, ADMIN_EDGE_TOKEN):
            # Hide existence
            raise HTTPException(status_code=404, detail="not found")

    # 3) Admin API key
    if not ADMIN_STATUS_KEY:
        raise HTTPException(status_code=404, detail="not found")
    sent = (request.headers.get("x-admin-key") or "").strip()
    if not sent or not hmac.compare_digest(sent, ADMIN_STATUS_KEY):
        raise HTTPException(status_code=403, detail="forbidden")

    # 4) Optional second factor
    if ADMIN_2FA_KEY:
        twofa = (request.headers.get("x-admin-2fa") or "").strip()
        if not twofa or not hmac.compare_digest(twofa, ADMIN_2FA_KEY):
            raise HTTPException(status_code=403, detail="forbidden")

    # Opsiyonel: TOTP (6 haneli) üçüncü faktör
    totp_secret = os.getenv("ADMIN_TOTP_SECRET", "").strip()
    if totp_secret:
        code = (request.headers.get("x-admin-totp") or "").strip()
        if not re.fullmatch(r"\d{6}", code or ""):
            raise HTTPException(status_code=403, detail="forbidden")
        try:
            import pyotp
            if not pyotp.TOTP(totp_secret).verify(code, valid_window=1):
                raise HTTPException(status_code=403, detail="forbidden")
        except Exception:
            raise HTTPException(status_code=403, detail="forbidden")



@app.get("/api/admin/bans")
def admin_list_bans(request: Request):
    """List active bans (hashed keys). Requires x-admin-key header."""
    _require_admin(request)
    if not ban_db:
        return {"enabled": False, "count": 0, "bans": []}
    bans = ban_db.list_active(limit=200)
    # Return minimal info (no IPs). keys are salted hashes.
    return {
        "enabled": bool(wafban_cfg.ban_enabled),
        "count": len(bans),
        "bans": [
            {
                "key": b.key,
                "reason": b.reason,
                "expires_in_sec": max(0, int(b.until_ts - time.time())),
            }
            for b in bans
        ],
    }


@app.post("/api/admin/bans/clear")
def admin_clear_bans(request: Request):
    """Clear all bans. Requires x-admin-key header."""
    _require_admin(request)
    if not ban_db:
        return {"ok": True, "cleared": 0}
    cleared = ban_db.clear_all()
    return {"ok": True, "cleared": cleared}


@app.post("/api/admin/bans/unban")
def admin_unban(request: Request, payload: dict):
    """Unban a specific key. Requires x-admin-key header."""
    _require_admin(request)
    key = (payload.get("key") or "").strip()
    if not key:
        raise HTTPException(status_code=400, detail="key required")
    if not ban_db:
        return {"ok": True, "removed": 0}
    removed = ban_db.unban(key)
    return {"ok": True, "removed": removed}

# --- Admin: Security Panel ---------------------------------------------------

@app.get("/api/admin/security/events")
def admin_security_events(
    request: Request,
    limit: int = 200,
):
    _require_admin(request)
    return {"events": security_events.recent(limit=limit)}


@app.get("/api/admin/security/summary")
def admin_security_summary(
    request: Request,
    minutes: int = 60,
):
    _require_admin(request)
    return security_events.summary(minutes=minutes)


@app.get("/api/admin/security/lockdown")
def admin_lockdown_status(request: Request):
    """Returns current lockdown state. Requires admin headers."""
    _require_admin(request)
    return lockdown_mgr.status()


@app.post("/api/admin/security/lockdown")
def admin_lockdown_action(request: Request, payload: dict):
    """Manual control for lockdown (force/deactivate). Requires admin headers."""
    _require_admin(request)
    action = str(payload.get("action") or "").strip().lower()
    if action in {"deactivate", "off", "disable", "stop"}:
        lockdown_mgr.deactivate(reason="manual")
    elif action in {"activate", "on", "enable", "force"}:
        ttl = payload.get("ttl_sec")
        try:
            ttl_i = int(ttl) if ttl is not None else int(LOCKDOWN_TTL_SEC)
        except Exception:
            ttl_i = int(LOCKDOWN_TTL_SEC)
        lockdown_mgr.force(ttl_sec=ttl_i, reason="manual")
    else:
        raise HTTPException(status_code=400, detail="action must be activate|deactivate")

    return lockdown_mgr.status()

@app.get("/api/admin/selfcheck")
def admin_selfcheck(request: Request):
    """Admin-only: lightweight runtime self-check (no secrets)."""
    _require_admin(request)

    return {
        "ok": True,
        "ts": int(time.time()),
        "python": platform.python_version(),
        "app": {
            "name": (_env_str("APP_NAME") or "Sanal Mülakatım"),
            "public_base_url": (_env_str("PUBLIC_BASE_URL") or "").rstrip("/"),
        },
        "features": {
            "captcha_enabled": bool(_captcha_enabled()),
            "smtp_enabled": bool(_smtp_enabled()),
            "payment_provider": _payment_provider(),
            "iyzico_configured": bool(_iyzico_enabled()),
            "stripe_configured": bool(_stripe_enabled()),
            "ocr_available": bool(fitz is not None),
            "admin_totp_enabled": bool(os.getenv("ADMIN_TOTP_SECRET", "").strip()),
            "trusted_proxy_headers": bool(TRUST_PROXY_HEADERS),
            "origin_guard": bool(ORIGIN_GUARD_ENABLED),
            "security_headers": bool(SECURITY_HEADERS),
            "hsts": bool(HSTS),
            "api_docs_enabled": bool(ENABLE_API_DOCS),
            "allow_token_in_url": bool(_env_bool("ALLOW_TOKEN_IN_URL", False)),
        },
        "limits": {
            "free_evals_total": _env_int("FREE_EVALS_TOTAL", 3),
            "free_ocr_per_day": _env_int("FREE_OCR_PER_DAY", 2),
            "rate_limit_default_per_min": _env_int("RATE_LIMIT_DEFAULT_PER_MIN", _env_int("RATE_LIMIT_PER_MINUTE", 60)),
            "max_sessions_total": _env_int("MAX_SESSIONS_TOTAL", 2000),
            "max_active_sessions_per_client": _env_int("MAX_ACTIVE_SESSIONS_PER_CLIENT", 3),
        },
        "inflight": {
            "START_MAX_INFLIGHT_GLOBAL": _env_int("START_MAX_INFLIGHT_GLOBAL", 6),
            "EVAL_MAX_INFLIGHT_GLOBAL": _env_int("EVAL_MAX_INFLIGHT_GLOBAL", 6),
            "NEXT_MAX_INFLIGHT_GLOBAL": _env_int("NEXT_MAX_INFLIGHT_GLOBAL", 6),
            "TRANSCRIBE_MAX_INFLIGHT_GLOBAL": _env_int("TRANSCRIBE_MAX_INFLIGHT_GLOBAL", 3),
            "PARSE_PDF_MAX_INFLIGHT_GLOBAL": _env_int("PARSE_PDF_MAX_INFLIGHT_GLOBAL", 2),
            "OCR_MAX_INFLIGHT_GLOBAL": _env_int("OCR_MAX_INFLIGHT_GLOBAL", 2),
        },
    }



@app.get("/admin", include_in_schema=False)
def admin_redirect():
    return RedirectResponse(url="/admin/security", status_code=302)

@app.get("/admin/security", include_in_schema=False)
def admin_security_panel(request: Request):
    require_admin_panel_ip(request)
    # Extra defence: if reverse proxy injects an edge token, require it here too.
    if ADMIN_EDGE_TOKEN:
        edge = (request.headers.get("x-admin-edge-token") or "").strip()
        if not edge or not hmac.compare_digest(edge, ADMIN_EDGE_TOKEN):
            raise HTTPException(status_code=404, detail="not found")
    # UI: basit bir panel (admin key + opsiyonel 2FA ile API'den veri çeker)
    return FileResponse(os.path.join(STATIC_DIR, "security_panel.html"))




@app.get("/api/usage")
def usage(ctx: ClientCtx = Depends(get_client_ctx)):
    used_daily = usage_db.get_usage(ctx.client_id)
    used_total = usage_db.get_total_usage(ctx.client_id)
    # FREE evals are TOTAL trials (not daily)
    lim_eval = _env_int("FREE_EVALS_TOTAL", 3)
    # Ses → yazı FREE'de dahil (ayrı kota yok). Rate limit yine geçerli.
    lim_tr = 0
    lim_ocr = _env_int("FREE_OCR_PER_DAY", 2)

    def rem(used_n: int, lim_n: int) -> Optional[int]:
        if ctx.is_pro:
            return None
        if lim_n <= 0:
            return None
        return max(0, lim_n - used_n)

    return {
        "client_id": ctx.client_id,
        "plan": "PRO" if ctx.is_pro else "FREE",
        "used": {
            "eval": int(used_total.get("eval", 0)),
            "transcribe": int(used_daily.get("transcribe", 0)),
            "ocr": int(used_daily.get("ocr", 0)),
        },
        "limits": {
            "eval": None if ctx.is_pro else lim_eval,
            "transcribe": None,
            "ocr": None if ctx.is_pro else lim_ocr,
        },
        "remaining": {
            "eval": rem(int(used_total.get("eval", 0)), lim_eval),
            "transcribe": None,
            "ocr": rem(int(used_daily.get("ocr", 0)), lim_ocr),
        },
    }

class StartRequest(BaseModel):
    role: str = Field(min_length=1, max_length=100)
    seniority: str = Field(min_length=1, max_length=50)
    language: str = Field(min_length=1, max_length=20)
    n_questions: int = Field(ge=1, le=10)
    cv_text: str = ""

class StartResponse(BaseModel):
    session_id: str
    index: int
    total: int
    question: Dict[str, Any]

@app.post("/api/start", response_model=StartResponse)
def start(req: StartRequest, ctx: ClientCtx = Depends(get_client_ctx)):
    enforce_rate_limit(ctx, "start")
    _enforce_session_limits(ctx)

    client = _get_client()

    sid = str(uuid.uuid4())
    sess = InterviewSession(
        id=sid,
        owner_client_id=ctx.client_id,
        role=req.role.strip(),
        seniority=req.seniority.strip(),
        language=req.language.strip(),
        n_questions=req.n_questions,
        cv_text=req.cv_text or "",
        questions=[],
        answers=[],
        current_index=0,
    )

    with inflight("start", ctx):
        q = _generate_question(
        client,
        role=sess.role,
        seniority=sess.seniority,
        language=sess.language,
        cv_text=sess.cv_text,
        asked_so_far=[],
        focus=None,
    )
    sess.questions.append(q)
    SESSIONS[sid] = sess

    return StartResponse(session_id=sid, index=1, total=sess.n_questions, question=q)

class EvaluateRequest(BaseModel):
    session_id: str
    answer: str = Field(min_length=1, max_length=8000)

@app.post("/api/evaluate")
def evaluate(req: EvaluateRequest, ctx: ClientCtx = Depends(get_client_ctx)):
    enforce_rate_limit(ctx, "eval")
    enforce_daily_limit(ctx, "eval")

    sess = SESSIONS.get(req.session_id)
    if not sess:
        raise HTTPException(status_code=404, detail="Oturum bulunamadı. Yeniden 'Mülakatı Başlat' yap.")

    # Session ownership guard (prevents guessing/reuse across clients)
    if getattr(sess, "owner_client_id", "") and sess.owner_client_id != ctx.client_id:
        raise HTTPException(status_code=404, detail="Oturum bulunamadı.")

    client = _get_client()

    if sess.current_index >= len(sess.questions):
        raise HTTPException(status_code=400, detail="Aktif soru yok.")

    q = sess.questions[sess.current_index]
    with inflight("eval", ctx):
        fb = _evaluate_answer(
        client,
        role=sess.role,
        seniority=sess.seniority,
        language=sess.language,
        question=q,
        answer=req.answer.strip(),
    )

    charge_usage(ctx, "eval")

    sess.answers.append({
        "index": sess.current_index,
        "question_id": q.get("id"),
        "answer": req.answer.strip(),
        "feedback": fb,
        "ts": int(time.time()),
    })
    sess.last_focus = fb.get("focus_area")

    return {"ok": True, "feedback": fb}

class NextRequest(BaseModel):
    session_id: str

@app.post("/api/next")
def next_question(req: NextRequest, ctx: ClientCtx = Depends(get_client_ctx)):
    enforce_rate_limit(ctx, "next")

    sess = SESSIONS.get(req.session_id)
    if not sess:
        raise HTTPException(status_code=404, detail="Oturum bulunamadı.")

    # Session ownership guard
    if getattr(sess, "owner_client_id", "") and sess.owner_client_id != ctx.client_id:
        raise HTTPException(status_code=404, detail="Oturum bulunamadı.")

    sess.current_index += 1
    if sess.current_index >= sess.n_questions:
        # Cleanup completed sessions (prevents memory growth)
        SESSIONS.pop(req.session_id, None)
        return {"ok": True, "done": True}

    if sess.current_index < len(sess.questions):
        q = sess.questions[sess.current_index]
        return {"ok": True, "done": False, "index": sess.current_index + 1, "total": sess.n_questions, "question": q}

    client = _get_client()

    asked_texts = [qq.get("question", "") for qq in sess.questions]
    with inflight("next", ctx):
        q = _generate_question(
        client,
        role=sess.role,
        seniority=sess.seniority,
        language=sess.language,
        cv_text=sess.cv_text,
        asked_so_far=asked_texts,
        focus=sess.last_focus,
    )
    sess.questions.append(q)
    return {"ok": True, "done": False, "index": sess.current_index + 1, "total": sess.n_questions, "question": q}

@app.post("/api/transcribe")
async def transcribe(request: Request, file: UploadFile = File(...), language: str = "tr", ctx: ClientCtx = Depends(get_client_ctx)):
    enforce_rate_limit(ctx, "transcribe")
    enforce_daily_limit(ctx, "transcribe")

    client = _get_client()
    audio_bytes = await file.read()

    # Hard cap to avoid huge uploads / abuse
    audio_max_mb = _env_int("AUDIO_MAX_MB", 12)
    if len(audio_bytes) > max(1, audio_max_mb) * 1024 * 1024:
        raise HTTPException(status_code=413, detail="audio_too_large")
    if not audio_bytes or len(audio_bytes) < 5000:
        return {"text": "", "warning": "Kayıt çok kısa/boş görünüyor. 2-3 sn net konuşup tekrar dene."}

    model = (_env_str("OPENAI_TRANSCRIBE_MODEL") or "gpt-4o-mini-transcribe").strip()

    bio = io.BytesIO(audio_bytes)
    bio.name = file.filename or "audio.webm"

    try:
        with inflight("transcribe", ctx):
            tr = await asyncio.to_thread(client.audio.transcriptions.create, model=model, file=bio)
        text = tr if isinstance(tr, str) else getattr(tr, "text", "")
        charge_usage(ctx, "transcribe")
        return {"text": (text or "").strip()}
    except Exception:
        try:
            bio.seek(0)
            with inflight("transcribe", ctx):
                tr = await asyncio.to_thread(client.audio.transcriptions.create, model="whisper-1", file=bio)
            text = tr if isinstance(tr, str) else getattr(tr, "text", "")
            charge_usage(ctx, "transcribe")
            return {"text": (text or "").strip(), "warning": "Transcribe fallback (whisper-1) kullanıldı."}
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Yazıya çevirme başarısız: {type(e).__name__}: {e}")

@app.post("/api/parse_pdf")
async def parse_pdf(file: UploadFile = File(...), language: str = "tr", ctx: ClientCtx = Depends(get_client_ctx)):
    enforce_rate_limit(ctx, "parse_pdf")
    # Basic upload validation (prevents random file uploads).
    ct = (file.content_type or "").lower()
    fn = (file.filename or "").lower()
    if ct and ("pdf" not in ct) and (not fn.endswith(".pdf")):
        raise HTTPException(status_code=400, detail="Sadece PDF yükleyebilirsin.")


    pdf_bytes = await file.read()

    # Basic file signature check: real PDFs start with "%PDF-"
    # (content-type alone can be spoofed).
    if not pdf_bytes.startswith(b"%PDF-"):
        raise HTTPException(status_code=400, detail="invalid_pdf_signature")
    if not pdf_bytes:
        raise HTTPException(status_code=400, detail="PDF boş.")

    max_mb = float(MAX_PDF_MB)
    if max_mb > 0 and len(pdf_bytes) > int(max_mb * 1024 * 1024):
        raise HTTPException(status_code=413, detail=f"PDF çok büyük. Maksimum {max_mb:g} MB.")

    max_pages = int(MAX_PDF_PAGES)

    # 1) pypdf
    text_parts: List[str] = []
    try:
        reader = PdfReader(io.BytesIO(pdf_bytes))
        if getattr(reader, "is_encrypted", False):
            raise HTTPException(status_code=400, detail="PDF şifreli/encrypted görünüyor. Şifresiz PDF yükle.")
        for i, page in enumerate(reader.pages):
            if max_pages and i >= max_pages:
                break
            t = page.extract_text() or ""
            if t.strip():
                text_parts.append(t)
    except HTTPException:
        raise
    except Exception:
        pass

    text = _clean_text("\n".join(text_parts))
    if text:
        return {"text": text, "method": "pypdf"}

    # PyMuPDF (fitz) yoksa burada dur.
    # Bu durumda taranmış PDF (metinsiz) için OCR yapamayız ve bazı PDF'lerde daha iyi metin çıkarımı da mümkün olmaz.
    if fitz is None:
        raise HTTPException(
            status_code=400,
            detail="PDF metni çıkarılamadı (PDF taranmış olabilir). OCR desteği için PyMuPDF kur: pip install pymupdf",
        )

    # 2) pymupdf text
    try:
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        buf = []
        for i in range(min(doc.page_count, max_pages or doc.page_count)):
            t = doc.load_page(i).get_text("text") or ""
            if t.strip():
                buf.append(t)
        doc.close()
        text = _clean_text("\n".join(buf))
        if text:
            return {"text": text, "method": "pymupdf"}
    except Exception:
        pass

    # 3) OCR fallback (counts toward OCR daily limit)
    enforce_daily_limit(ctx, "ocr")

    client = _get_client()
    ocr_pages = _env_int("OCR_MAX_PAGES", 2)
    zoom = _env_float("OCR_ZOOM", 2.0)

    try:
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        images = []
        for i in range(min(ocr_pages, doc.page_count)):
            page = doc.load_page(i)
            pix = page.get_pixmap(matrix=fitz.Matrix(zoom, zoom), alpha=False)
            images.append(pix.tobytes("png"))
        doc.close()
        if not images:
            raise HTTPException(status_code=400, detail="PDF sayfa bulunamadı.")
        with inflight("ocr", ctx):
            ocr_text = await asyncio.to_thread(_ocr_images_with_openai, client, images, language=language)
        ocr_text = _clean_text(ocr_text)
        if not ocr_text:
            raise HTTPException(status_code=400, detail="OCR metin çıkaramadı. PDF çok düşük kalite olabilir.")
        charge_usage(ctx, "ocr")
        return {"text": ocr_text, "method": "ocr"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF OCR başarısız: {type(e).__name__}: {e}")

# -----------------------------
# Payments (optional): stripe / iyzico
# -----------------------------

def _stripe_enabled() -> bool:
    return bool(_env_str("STRIPE_SECRET_KEY")) and bool(_env_str("STRIPE_PRICE_ID"))

def _iyzico_enabled() -> bool:
    return bool(_env_str("IYZICO_API_KEY")) and bool(_env_str("IYZICO_SECRET_KEY")) and bool(_env_str("IYZICO_BASE_URL"))

def _payment_provider() -> str:
    p = (_env_str("PAYMENT_PROVIDER") or "").strip().lower()
    if p:
        return p
    # Auto: prefer iyzico if configured, else stripe
    if _iyzico_enabled():
        return "iyzico"
    return "stripe"

def _require_https_public_base_url(base_url: str) -> None:
    if not base_url.startswith("https://"):
        raise HTTPException(
            status_code=400,
            detail=(
                "iyzico Checkout Form için PUBLIC_BASE_URL https://... olmalı (callbackUrl SSL ister). "
                "Local test için ngrok gibi bir https tüneli kullan."
            ),
        )

def _iyzico_make_headers(uri_path: str, body_json: str, random_key: str | None = None) -> Dict[str, str]:
    """Build iyzico HMACSHA256 headers (IYZWSv2)."""
    api_key = _env_str("IYZICO_API_KEY")
    secret_key = _env_str("IYZICO_SECRET_KEY")
    rk = random_key or (str(int(time.time() * 1000)) + uuid.uuid4().hex[:6])
    payload = rk + uri_path + (body_json or "")
    encrypted = hmac.new(secret_key.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    auth_string = f"apiKey:{api_key}&randomKey:{rk}&signature:{encrypted}"
    b64 = base64.b64encode(auth_string.encode("utf-8")).decode("utf-8")
    return {
        "Authorization": "IYZWSv2 " + b64,
        "x-iyzi-rnd": rk,
        "Content-Type": "application/json",
    }

def _iyzico_post(uri_path: str, body: Dict[str, Any]) -> Dict[str, Any]:
    base_url = (_env_str("IYZICO_BASE_URL") or "https://sandbox-api.iyzipay.com").rstrip("/")
    body_json = json.dumps(body or {}, separators=(",", ":"), ensure_ascii=False)
    headers = _iyzico_make_headers(uri_path, body_json)
    url = base_url + uri_path
    try:
        r = requests.post(url, headers=headers, data=body_json.encode("utf-8"), timeout=_env_int("IYZICO_TIMEOUT", 25))
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"iyzico istek hatası: {type(e).__name__}: {e}")

    try:
        j = r.json()
    except Exception:
        raise HTTPException(status_code=502, detail=f"iyzico cevap JSON değil (HTTP {r.status_code}).")

    if r.status_code >= 400:
        msg = (j.get("errorMessage") if isinstance(j, dict) else None) or str(j)
        raise HTTPException(status_code=502, detail=f"iyzico hata (HTTP {r.status_code}): {msg}")
    return j

def _iyzico_expect_success(j: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(j, dict):
        raise HTTPException(status_code=502, detail="iyzico cevap formatı beklenmedik.")
    if (j.get("status") or "").lower() != "success":
        msg = (j.get("errorMessage") or j.get("errorCode") or "Bilinmeyen hata")
        raise HTTPException(status_code=502, detail=f"iyzico başarısız: {msg}")
    return j

@app.post("/api/billing/create_checkout")
async def create_checkout(request: Request, ctx: ClientCtx = Depends(get_client_ctx)):
    """Create a hosted checkout URL.

    - stripe: returns Stripe Checkout session.url
    - iyzico: returns iyzico Checkout Form paymentPageUrl

    Frontend always expects: { url: "https://..." }
    """
    enforce_rate_limit(ctx, "billing")

    provider = _payment_provider()

    # --- Stripe ---
    if provider == "stripe":
        if not _stripe_enabled():
            raise HTTPException(
                status_code=400,
                detail="Stripe ayarlı değil. .env içine STRIPE_SECRET_KEY ve STRIPE_PRICE_ID gir (veya PAYMENT_PROVIDER=iyzico yap).",
            )

        try:
            import stripe  # type: ignore
        except Exception:
            raise HTTPException(status_code=500, detail="stripe paketi bulunamadı. requirements.txt ile yükle.")

        stripe.api_key = _env_str("STRIPE_SECRET_KEY")
        price_id = _env_str("STRIPE_PRICE_ID")
        base_url = _env_str("PUBLIC_BASE_URL", "http://localhost:5555").rstrip("/")

        success_url = f"{base_url}/success?session_id={{CHECKOUT_SESSION_ID}}"
        cancel_url = f"{base_url}/cancel"

        try:
            session = stripe.checkout.Session.create(
                mode="payment",
                line_items=[{"price": price_id, "quantity": 1}],
                success_url=success_url,
                cancel_url=cancel_url,
                metadata={"client_id": ctx.client_id},
            )
            return {"url": session.url, "provider": "stripe"}
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Stripe checkout oluşturulamadı: {type(e).__name__}: {e}")

    # --- iyzico (Checkout Form / Hosted Payment Page) ---
    if provider == "iyzico":
        if not _iyzico_enabled():
            raise HTTPException(
                status_code=400,
                detail=(
                    "iyzico ayarlı değil. .env içine IYZICO_API_KEY / IYZICO_SECRET_KEY / IYZICO_BASE_URL gir. "
                    "(Sandbox için baseUrl: https://sandbox-api.iyzipay.com)"
                ),
            )

        base_url = _env_str("PUBLIC_BASE_URL", "http://localhost:5555").rstrip("/")
        _require_https_public_base_url(base_url)

        # Optional body: { email }
        data = {}
        try:
            data = await request.json()
        except Exception:
            data = {}

        email = ""
        if isinstance(data, dict):
            email = str(data.get("email") or "").strip()

        order_id = "ord_" + uuid.uuid4().hex[:24]
        usage_db.create_payment_order(order_id=order_id, provider="iyzico", client_id=ctx.client_id, email=email or None)

        amount = float(_env_float("PRO_PRICE_TRY", 199.0))
        amount = round(amount, 2)
        title = (_env_str("PRO_TITLE") or "Pro Erişim").strip() or "Pro Erişim"

        callback_url = f"{base_url}/api/billing/iyzico/callback?order_id={order_id}"

        # Minimal buyer details (you may want to collect these properly in production)
        buyer_name = (_env_str("IYZICO_BUYER_NAME") or "Kullanıcı").strip() or "Kullanıcı"
        buyer_surname = (_env_str("IYZICO_BUYER_SURNAME") or "").strip() or "-"
        buyer_identity = (_env_str("IYZICO_IDENTITY_NUMBER") or "11111111111").strip() or "11111111111"
        buyer_gsm = (_env_str("IYZICO_GSM_NUMBER") or "+905350000000").strip() or "+905350000000"
        buyer_email = email or (_env_str("IYZICO_FALLBACK_EMAIL") or "user@example.com").strip() or "user@example.com"

        ip = _get_ip(request)

        addr_city = (_env_str("IYZICO_CITY") or "Istanbul").strip() or "Istanbul"
        addr_country = (_env_str("IYZICO_COUNTRY") or "Turkey").strip() or "Turkey"
        addr_zip = (_env_str("IYZICO_ZIP") or "34000").strip() or "34000"
        addr_text = (_env_str("IYZICO_ADDRESS") or "Adres bilgisi").strip() or "Adres bilgisi"

        init_payload: Dict[str, Any] = {
            "locale": "tr",
            "conversationId": order_id,
            "price": amount,
            "paidPrice": amount,
            "currency": "TRY",
            "basketId": order_id,
            "paymentGroup": "PRODUCT",
            "callbackUrl": callback_url,
            "enabledInstallments": [1],
            "buyer": {
                "id": ctx.client_id[:50],
                "name": buyer_name,
                "surname": buyer_surname,
                "identityNumber": buyer_identity,
                "email": buyer_email,
                "gsmNumber": buyer_gsm,
                "registrationAddress": addr_text,
                "ip": ip,
                "city": addr_city,
                "country": addr_country,
                "zipCode": addr_zip,
            },
            "billingAddress": {
                "contactName": f"{buyer_name} {buyer_surname}".strip(),
                "city": addr_city,
                "country": addr_country,
                "address": addr_text,
                "zipCode": addr_zip,
            },
            "shippingAddress": {
                "contactName": f"{buyer_name} {buyer_surname}".strip(),
                "city": addr_city,
                "country": addr_country,
                "address": addr_text,
                "zipCode": addr_zip,
            },
            "basketItems": [
                {
                    "id": "PRO",
                    "name": title,
                    "category1": "Digital",
                    "itemType": "VIRTUAL",
                    "price": amount,
                }
            ],
        }

        uri = "/payment/iyzipos/checkoutform/initialize/auth/ecom"
        j = _iyzico_post(uri, init_payload)
        j = _iyzico_expect_success(j)

        pay_url = (j.get("paymentPageUrl") or "").strip()
        if not pay_url:
            # Fallback: some responses might not include paymentPageUrl
            token = (j.get("token") or "").strip()
            if token:
                # Known sandbox URL pattern from docs
                pay_url = f"https://sandbox-cpp.iyzipay.com?token={token}&lang=tr"

        if not pay_url:
            raise HTTPException(status_code=502, detail=f"iyzico paymentPageUrl alınamadı: {j}")

        return {"url": pay_url, "provider": "iyzico", "order_id": order_id}

    raise HTTPException(status_code=400, detail="PAYMENT_PROVIDER geçersiz. stripe | iyzico")

@app.post("/api/billing/webhook")
async def stripe_webhook(request: Request):
    if not _stripe_enabled():
        raise HTTPException(status_code=400, detail="Stripe ayarlı değil.")
    wh_secret = _env_str("STRIPE_WEBHOOK_SECRET")
    if not wh_secret:
        raise HTTPException(status_code=400, detail="STRIPE_WEBHOOK_SECRET eksik.")

    try:
        import stripe  # type: ignore
    except Exception:
        raise HTTPException(status_code=500, detail="stripe paketi bulunamadı.")

    payload = await request.body()
    sig = request.headers.get("stripe-signature")
    try:
        event = stripe.Webhook.construct_event(payload=payload, sig_header=sig, secret=wh_secret)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Webhook doğrulaması başarısız: {type(e).__name__}: {e}")

    etype = event.get("type")
    if etype == "checkout.session.completed":
        obj = event["data"]["object"]
        session_id = obj.get("id")
        client_id = None
        md = obj.get("metadata") or {}
        if isinstance(md, dict):
            client_id = md.get("client_id")
        token = "pro_" + str(uuid.uuid4()).replace("-", "")[:20]
        usage_db.add_pro_token(token=token, client_id=client_id, provider="stripe", provider_ref=session_id, stripe_session_id=session_id)
        logger.info(f"Stripe completed: session={session_id} client={client_id} token={token}")
        return {"ok": True}

    return {"ok": True}



@app.api_route("/api/billing/iyzico/callback", methods=["GET", "POST"])
async def iyzico_callback(request: Request, order_id: str):
    """iyzico redirects (POST) to callbackUrl and posts a `token`.

    We then call CF-Retrieve with that token to verify payment result.
    On success, we generate/store a Pro token and redirect user to /success.
    """
    if not _iyzico_enabled():
        return HTMLResponse(
            "<h1>iyzico ayarlı değil.</h1><p>Sunucu tarafında IYZICO_API_KEY / IYZICO_SECRET_KEY eksik.</p>",
            status_code=400,
        )

    order_id = (order_id or "").strip()
    if not order_id:
        return HTMLResponse("<h1>order_id eksik.</h1>", status_code=400)

    token = ""
    if request.method == "GET":
        token = (request.query_params.get("token") or "").strip()
    else:
        # iyzico generally POSTs as form-data
        try:
            form = await request.form()
            token = str(form.get("token") or "").strip()
        except Exception:
            token = ""
        if not token:
            # fallback to JSON
            try:
                body = await request.json()
                if isinstance(body, dict):
                    token = str(body.get("token") or "").strip()
            except Exception:
                token = ""

    if not token:
        return HTMLResponse(
            "<h1>token bulunamadı.</h1><p>iyzico callback POST gövdesinde token bekleniyor.</p>",
            status_code=400,
        )

    # Make sure we have a payment order record (best-effort)
    order = usage_db.get_payment_order(order_id)
    if not order:
        usage_db.create_payment_order(order_id=order_id, provider="iyzico", client_id=None, email=None)
        order = usage_db.get_payment_order(order_id)

    # Track callback arrival (idempotent)
    usage_db.update_payment_order(order_id, status="CALLBACK_RECEIVED", provider_token=token, last_error=None)

    # If already processed, don't mint a new token
    existing = usage_db.get_token_by_provider_ref("iyzico", order_id)
    if existing:
        usage_db.update_payment_order(order_id, status="TOKEN_ISSUED")
        return HTMLResponse(
            f"""<!doctype html><html><head><meta charset='utf-8'>
<meta http-equiv='refresh' content='0;url=/success?provider=iyzico&ref={order_id}'>
<title>Yönlendiriliyor</title></head><body>
<p>Yönlendiriliyor… <a href='/success?provider=iyzico&ref={order_id}'>Devam</a></p>
</body></html>""",
            status_code=200,
        )

    # Verify payment result with CF-Retrieve
    uri = "/payment/iyzipos/checkoutform/auth/ecom/detail"
    retrieve_payload: Dict[str, Any] = {"locale": "tr", "conversationId": order_id, "token": token}
    resp = _iyzico_post(uri, retrieve_payload)

    # Store raw response for support/debug (best-effort; avoid crashing if JSON has weird types)
    try:
        usage_db.update_payment_order(order_id, raw_response=json.dumps(resp, ensure_ascii=False))
    except Exception:
        pass

    status = (resp.get("status") or "").lower() if isinstance(resp, dict) else ""
    pay_status = (resp.get("paymentStatus") or "").upper() if isinstance(resp, dict) else ""

    if status == "success" and pay_status == "SUCCESS":
        usage_db.update_payment_order(order_id, status="VERIFIED_SUCCESS", last_error=None)

        order = usage_db.get_payment_order(order_id)
        client_id = order.get("client_id") if isinstance(order, dict) else None

        pro_token = "pro_" + uuid.uuid4().hex[:20]
        usage_db.add_pro_token(token=pro_token, client_id=client_id, provider="iyzico", provider_ref=order_id)

        # Record final state (idempotency/support)
        payment_id = ""
        if isinstance(resp, dict):
            payment_id = str(resp.get("paymentId") or resp.get("payment_id") or "").strip()
        usage_db.update_payment_order(
            order_id,
            status="TOKEN_ISSUED",
            provider_payment_id=(payment_id or None),
        )
        logger.info(f"iyzico SUCCESS: order={order_id} client={client_id} token={pro_token}")

        base_url = _env_str("PUBLIC_BASE_URL", "http://localhost:5555").rstrip("/")
        emailed = False
        if isinstance(order, dict):
            emailed = _auto_email_token_best_effort(order.get("email"), pro_token, base_url=base_url)

        success_url = f"/success?provider=iyzico&ref={order_id}" + ("&emailed=1" if emailed else "")

        return HTMLResponse(
            f"""<!doctype html><html><head><meta charset='utf-8'>
<meta http-equiv='refresh' content='0;url={success_url}'>
<title>Ödeme Başarılı</title></head><body>
<p>Ödeme başarılı ✅ Yönlendiriliyor…</p>
<p><a href='{success_url}'>Devam etmek için tıkla</a></p>
</body></html>""",
            status_code=200,
        )

    # Failure
    err = ""
    if isinstance(resp, dict):
        err = (resp.get("errorMessage") or resp.get("errorCode") or resp.get("paymentStatus") or "").strip()

    logger.warning(f"iyzico FAIL: order={order_id} status={status} paymentStatus={pay_status} err={err}")

    usage_db.update_payment_order(order_id, status="VERIFIED_FAIL", last_error=(err or None))

    return HTMLResponse(
        f"""<!doctype html><html><head><meta charset='utf-8'>
<meta http-equiv='refresh' content='0;url=/cancel'>
<title>Ödeme Başarısız</title></head><body>
<h1>Ödeme tamamlanamadı</h1>
<p>{err or 'Lütfen tekrar dene.'}</p>
<p><a href='/'>Ana sayfaya dön</a></p>
</body></html>""",
        status_code=200,
    )
@app.get("/api/billing/redeem")
def redeem(
    session_id: str | None = None,
    provider: str | None = None,
    ref: str | None = None,
    ctx: ClientCtx = Depends(get_client_ctx),
):
    """Redeem a Pro token after payment.

    - Stripe legacy: /api/billing/redeem?session_id=...
    - Generic: /api/billing/redeem?provider=iyzico&ref=order_id
    """
    enforce_rate_limit(ctx, "redeem")

    prov = (provider or "").strip().lower()
    if prov:
        if not ref:
            raise HTTPException(status_code=400, detail="ref eksik. Örn: ?provider=iyzico&ref=order_id")
        token = usage_db.get_token_by_provider_ref(prov, ref)
        if not token:
            raise HTTPException(
                status_code=404,
                detail="Bu ödeme için token bulunamadı. Ödeme henüz doğrulanmamış olabilir (callback/webhook gecikmiş olabilir).",
            )
        return {"token": token}

    if not session_id:
        raise HTTPException(status_code=400, detail="session_id bulunamadı.")

    token = usage_db.get_token_by_stripe_session(session_id)
    if not token:
        raise HTTPException(status_code=404, detail="Bu session_id için token bulunamadı. Stripe webhook ayarlarını kontrol et.")
    return {"token": token}





# -----------------------------
# SMTP (optional): send Pro token via email
# -----------------------------
_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")

def _smtp_enabled() -> bool:
    host = _env_str("SMTP_HOST")
    port = _env_int("SMTP_PORT", 0)
    from_addr = _env_str("SMTP_FROM")
    return bool(host) and bool(port) and bool(from_addr)

def _send_email(to_email: str, subject: str, body: str) -> None:
    """Send a plaintext email using SMTP settings from .env.

    Best-effort: used for sending Pro token after payment.
    """
    host = _env_str("SMTP_HOST")
    port = _env_int("SMTP_PORT", 587)
    user = _env_str("SMTP_USER")
    pwd = _env_str("SMTP_PASS")
    from_email = _env_str("SMTP_FROM")
    from_name = (_env_str("SMTP_FROM_NAME") or _env_str("APP_NAME") or "Sanal Mülakatım").strip()

    use_tls = _env_int("SMTP_USE_TLS", 1) == 1
    use_ssl = _env_int("SMTP_USE_SSL", 0) == 1
    timeout = _env_int("SMTP_TIMEOUT", 20)

    if not host or not from_email:
        raise RuntimeError("SMTP ayarlı değil (SMTP_HOST/SMTP_FROM).")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = formataddr((from_name, from_email))
    msg["To"] = to_email
    msg.set_content(body or "")

    smtp = None
    try:
        if use_ssl:
            smtp = smtplib.SMTP_SSL(host, port, timeout=timeout)
        else:
            smtp = smtplib.SMTP(host, port, timeout=timeout)

        try:
            smtp.ehlo()
        except Exception:
            pass

        if use_tls and not use_ssl:
            smtp.starttls()
            try:
                smtp.ehlo()
            except Exception:
                pass

        if user and pwd:
            smtp.login(user, pwd)

        smtp.send_message(msg)
    finally:
        try:
            if smtp is not None:
                smtp.quit()
        except Exception:
            pass

def _auto_email_token_best_effort(email: str | None, token: str, *, base_url: str) -> bool:
    """Try sending token email; never raises to caller. Returns True if attempted+sent."""
    enabled = _env_int("AUTO_EMAIL_TOKEN_ON_PAYMENT", 1) == 1
    if not enabled:
        return False

    email = (email or "").strip()
    token = (token or "").strip()

    if not email or not _EMAIL_RE.match(email):
        return False
    if not token:
        return False
    if not _smtp_enabled():
        return False

    app_name = (_env_str("APP_NAME") or "Sanal Mülakatım").strip()
    base_url = (base_url or _env_str("PUBLIC_BASE_URL") or "http://localhost:5555").rstrip("/")

    subject = f"{app_name} • Pro Anahtarın"
    body = (
        f"Merhaba,\n\n"
        f"Ödemen başarıyla alındı ✅\n\n"
        f"Pro anahtarın:\n{token}\n\n"
        f"Uygulamada 'Pro Anahtarı' alanına yapıştırabilirsin:\n"
        f"{base_url}/app\n\n"
        f"— {app_name}\n"
    )

    try:
        _send_email(email, subject, body)
        logger.info(f"Pro token emailed: to={email}")
        return True
    except Exception as e:
        logger.warning(f"Auto email failed: {type(e).__name__}: {e}")
        return False

class EmailTokenRequest(BaseModel):
    email: str
    token: str

@app.post("/api/billing/email_token")
def email_token(req: EmailTokenRequest, ctx: ClientCtx = Depends(get_client_ctx)):
    """Send Pro token to user's email via SMTP (optional)."""
    enforce_rate_limit(ctx, "email_token")

    email = (req.email or "").strip()
    token = (req.token or "").strip()

    if not _EMAIL_RE.match(email):
        raise HTTPException(status_code=400, detail="Geçerli bir e-posta adresi gir.")

    # token must be valid (env allowlist OR DB)
    if token not in _ENV_PRO_TOKENS and not usage_db.is_pro_token(token):
        raise HTTPException(status_code=400, detail="Geçersiz Pro anahtarı.")

    # Store a hashed link for future recovery (best-effort)
    try:
        usage_db.link_email_to_token(email, token)
    except Exception:
        pass

    if not _smtp_enabled():
        raise HTTPException(
            status_code=400,
            detail="E-posta gönderimi ayarlı değil. backend/.env içine SMTP_HOST/SMTP_PORT/SMTP_FROM ekle.",
        )

    app_name = (_env_str("APP_NAME") or "Sanal Mülakatım").strip()
    base_url = (_env_str("PUBLIC_BASE_URL") or "http://localhost:5555").rstrip("/")

    subject = f"{app_name} • Pro Anahtarın"
    body = (
        f"Merhaba,\n\n"
        f"Pro anahtarın:\n{token}\n\n"
        f"Uygulamada 'Pro Anahtarı' alanına yapıştırabilirsin.\n"
        f"{base_url}/app\n\n"
        f"— {app_name}\n"
    )

    try:
        _send_email(email, subject, body)
    except Exception as e:
        logger.exception("Email send failed")
        raise HTTPException(status_code=500, detail=f"E-posta gönderilemedi: {type(e).__name__}: {e}")

    return {"ok": True}


# -----------------------------
# Pro recovery (magic link)
# -----------------------------

class RecoveryRequest(BaseModel):
    email: str
    captcha_token: Optional[str] = None


@app.post("/api/pro/recovery/request")
def pro_recovery_request(req: RecoveryRequest, request: Request, ctx: ClientCtx = Depends(get_client_ctx)):
    """Send a one-time recovery link to an email (if linked tokens exist).

    NOTE: We don't reveal whether the email has tokens, to reduce enumeration.
    """
    enforce_rate_limit(ctx, "recovery_request")

    # Optional CAPTCHA (prevents email-spam / recovery brute force)
    if CAPTCHA_REQUIRED_EMAIL:
        require_captcha_or_raise(request, req.captcha_token, purpose="pro_recovery")

    email = (req.email or "").strip()
    if not _EMAIL_RE.match(email):
        raise HTTPException(status_code=400, detail="Geçerli bir e-posta adresi gir.")

    # If SMTP isn't configured, we can't deliver the magic link.
    if not _smtp_enabled():
        raise HTTPException(
            status_code=400,
            detail="E-posta gönderimi ayarlı değil. backend/.env içine SMTP_HOST/SMTP_PORT/SMTP_FROM ekle.",
        )

    # Only send email if we have at least one linked token.
    # Still return OK regardless, to avoid revealing membership.
    tokens = []
    try:
        tokens = usage_db.get_tokens_for_email(email)
    except Exception:
        tokens = []

    sent = False
    if tokens:
        ttl_min = _env_int("RECOVERY_TOKEN_TTL_MIN", 15)
        try:
            raw = usage_db.create_recovery_link(email, ttl_minutes=ttl_min)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Recovery link üretilemedi: {type(e).__name__}")

        app_name = (_env_str("APP_NAME") or "Sanal Mülakatım").strip()
        base_url = (_env_str("PUBLIC_BASE_URL") or "http://localhost:5555").rstrip("/")
        link = f"{base_url}/recover#token={raw}"

        subject = f"{app_name} • Pro anahtar kurtarma"
        body = (
            "Merhaba,\n\n"
            "Pro anahtarlarını görmek için aşağıdaki linki aç: \n"
            f"{link}\n\n"
            f"Bu link {ttl_min} dakika geçerlidir ve tek kullanımlıktır.\n\n"
            f"— {app_name}\n"
        )

        try:
            _send_email(email, subject, body)
            sent = True
        except Exception as e:
            logger.exception("Recovery email send failed")
            # Don't leak more details
            raise HTTPException(status_code=500, detail=f"E-posta gönderilemedi: {type(e).__name__}")

    try:
        bk = ban_key_for_request(request, CLIENT_ID_SALT)
        security_events.log(
            "pro_recovery_request",
            ban_key=bk,
            client_id=ctx.client_id,
            method=request.method,
            path=request.url.path,
            status=200,
            weight=1,
            ua=request.headers.get("user-agent", ""),
            details={"sent": bool(sent)},
        )
    except Exception:
        pass

    return {"ok": True}




class RecoveryConsume(BaseModel):
    token: str


@app.post("/api/pro/recovery/consume")
def pro_recovery_consume_post(req: RecoveryConsume):
    """Consume a magic-link token (POST body) and return linked Pro tokens.

    Using POST avoids putting tokens into URLs (which can be logged by proxies).
    """
    token = (req.token or "").strip()
    if not token:
        raise HTTPException(status_code=400, detail="token eksik")

    email_hash = usage_db.consume_recovery_link(token)
    if not email_hash:
        raise HTTPException(status_code=400, detail="Link geçersiz veya süresi dolmuş.")

    tokens = usage_db.get_tokens_by_email_hash(email_hash)
    return {"tokens": tokens}


@app.get("/api/pro/recovery/consume")
def pro_recovery_consume(token: str):
    """Consume a magic link token and return linked Pro tokens.

    Not recommended: putting tokens in URLs can leak via proxy/server logs.
    This endpoint is disabled by default in production.
    """
    if (not DEBUG) and (not _env_bool("ALLOW_TOKEN_IN_URL", False)):
        raise HTTPException(status_code=404, detail="not found")
    token = (token or "").strip()
    if not token:
        raise HTTPException(status_code=400, detail="token eksik")

    email_hash = usage_db.consume_recovery_link(token)
    if not email_hash:
        raise HTTPException(status_code=400, detail="Link geçersiz veya süresi dolmuş.")

    tokens = usage_db.get_tokens_by_email_hash(email_hash)
    return {"tokens": tokens}


# -----------------------------
# Privacy: email-verified delete
# -----------------------------

class PrivacyDeleteRequest(BaseModel):
    email: str
    captcha_token: Optional[str] = None


class PrivacyDeleteConfirm(BaseModel):
    token: str


@app.post("/api/privacy/delete/request")
def privacy_delete_request(req: PrivacyDeleteRequest, request: Request, ctx: ClientCtx = Depends(get_client_ctx)):
    """Send a one-time delete confirmation link to the email.

    Response is intentionally generic to reduce email enumeration.
    """
    enforce_rate_limit(ctx, "privacy_delete_request")

    email = (req.email or "").strip()
    if not _EMAIL_RE.match(email):
        raise HTTPException(status_code=400, detail="Geçerli bir e-posta adresi gir.")

    # Optional captcha: blocks automated abuse of email sending.
    if CAPTCHA_REQUIRED_EMAIL:
        require_captcha_or_raise(request, req.captcha_token, purpose="privacy_delete_request")

    # Avoid sending emails to totally unknown addresses (spam-resistance).
    should_send = usage_db.email_has_any_data(email)

    token = None
    sent = False
    if should_send:
        token = usage_db.create_delete_link(email, ttl_minutes=PRIVACY_DELETE_TOKEN_TTL_MIN)
        link = f"{PUBLIC_BASE_URL.rstrip('/')}/delete#token={token}"

        subject = f"{APP_NAME} • Veri silme onayı"
        body = (
            "Merhaba,\n\n"
            "E-posta ile ilişkilendirilmiş verileri silmek/anonymize etmek için aşağıdaki bağlantıyı aç:\n"
            f"{link}\n\n"
            f"Bu bağlantı {PRIVACY_DELETE_TOKEN_TTL_MIN} dakika geçerlidir ve tek kullanımlıktır.\n\n"
            "Bu isteği sen yapmadıysan bu e-postayı yok sayabilirsin.\n\n"
            f"— {APP_NAME}\n"
        )

        try:
            _send_email(email, subject, body)
            sent = True
        except Exception:
            sent = False
            logger.exception("privacy delete email send failed")
            # Still return generic response (do not leak).

    # Security metrics
    try:
        bk = ban_key_for_request(request, CLIENT_ID_SALT)
        security_events.log(
            "privacy_delete_request",
            ban_key=bk,
            client_id=ctx.client_id,
            method=request.method,
            path=request.url.path,
            status=200,
            weight=1,
            ua=request.headers.get("user-agent", ""),
            details={
                "should_send": bool(should_send),
                "sent": bool(sent),
                "captcha_enabled": bool(_captcha_enabled()),
            },
        )
    except Exception:
        pass

    resp = {
        "ok": True,
        "message": "Eğer bu e-posta ile ilişkili veri varsa, silme bağlantısı gönderildi.",
    }
    if DEBUG_RETURN_PRIVACY_DELETE_TOKEN and token:
        resp["debug_token"] = token
    return resp


@app.post("/api/privacy/delete/confirm")
def privacy_delete_confirm(req: PrivacyDeleteConfirm, request: Request, ctx: ClientCtx = Depends(get_client_ctx)):
    """Consume a one-time token and anonymize email-linked data."""
    enforce_rate_limit(ctx, "privacy_delete_confirm")

    token = (req.token or "").strip()
    if not token:
        raise HTTPException(status_code=400, detail="token eksik")

    email_hash = usage_db.consume_delete_link(token)
    if not email_hash:
        raise HTTPException(status_code=400, detail="Link geçersiz veya süresi dolmuş.")

    try:
        stats = usage_db.anonymize_email_hash(email_hash)
    except Exception:
        logger.exception("privacy delete confirm failed")
        raise HTTPException(status_code=500, detail="İşlem sırasında hata oluştu.")

    try:
        bk = ban_key_for_request(request, CLIENT_ID_SALT)
        security_events.log(
            "privacy_delete_confirm",
            ban_key=bk,
            client_id=ctx.client_id,
            method=request.method,
            path=request.url.path,
            status=200,
            weight=1,
            ua=request.headers.get("user-agent", ""),
            details=stats,
        )
    except Exception:
        pass

    return {"ok": True, "removed": stats}


@app.post("/api/privacy/delete")
def privacy_delete_compat(req: PrivacyDeleteConfirm, request: Request, ctx: ClientCtx = Depends(get_client_ctx)):
    """Backward-compatible endpoint.

    New flow is email-verified; so this endpoint now only accepts a token.
    """
    return privacy_delete_confirm(req, request, ctx)
