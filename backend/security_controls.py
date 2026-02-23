"""Security controls for Sanal Mülakatım (Lite).

What this module provides
-------------------------
1) Basic WAF-style request inspection
   - Blocks obvious bot/scan patterns (path traversal, script tags in URL, common SQLi markers)
   - Avoids inspecting free-text bodies (CV/answers) to reduce false positives

2) Temporary ban list ("mini fail2ban" inside the app)
   - Tracks suspicious events per IP (stored as a hash, not raw IP)
   - Automatically bans for a configurable duration when a threshold is exceeded

This is intentionally conservative. The goal is to reduce noisy bot traffic
and opportunistic scans without breaking legitimate users.

Note: This is not a full WAF and does not replace:
- Keeping dependencies updated
- Proper network firewall rules
- Reverse proxy hardening and TLS
- Monitoring and alerting

"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import time
import urllib.parse
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence, Tuple
from starlette.types import ASGIApp, Receive, Scope, Send
from starlette.responses import JSONResponse


class _BodyTooLarge(Exception):
    pass


class BodySizeLimitMiddleware:
    """
    Request body boyutunu sınırlar.
    main.py: app.add_middleware(BodySizeLimitMiddleware, default_kb=...)
    """

    def __init__(self, app: ASGIApp, default_kb: int = 256):
        self.app = app
        self.max_bytes = int(default_kb) * 1024

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        # Hızlı blok: Content-Length varsa
        headers = {k.decode("latin1").lower(): v.decode("latin1") for k, v in scope.get("headers", [])}
        cl = headers.get("content-length")
        if cl and cl.isdigit() and int(cl) > self.max_bytes:
            return await JSONResponse({"detail": "Request body too large"}, status_code=413)(scope, receive, send)

        seen = 0

        async def limited_receive():
            nonlocal seen
            msg = await receive()
            if msg["type"] == "http.request":
                chunk = msg.get("body", b"")
                seen += len(chunk)
                if seen > self.max_bytes:
                    raise _BodyTooLarge()
            return msg

        try:
            return await self.app(scope, limited_receive, send)
        except _BodyTooLarge:
            return await JSONResponse({"detail": "Request body too large"}, status_code=413)(scope, receive, send)

def _env_bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "y", "on"}


def _env_int(name: str, default: int) -> int:
    v = os.environ.get(name)
    if v is None:
        return default
    try:
        return int(v)
    except ValueError:
        return default


def _env_csv_int_set(name: str, default: Sequence[int]) -> set[int]:
    v = os.environ.get(name)
    if not v:
        return set(default)
    out: set[int] = set()
    for part in v.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            out.add(int(part))
        except ValueError:
            continue
    return out or set(default)


@dataclass(frozen=True)
class WafBanConfig:
    # --- WAF ---
    waf_enabled: bool
    waf_block: bool
    waf_max_query_len: int
    waf_max_header_len: int
    waf_max_body_bytes: int

    # For endpoints that contain free-text (CV, answers, transcripts), we avoid body inspection.
    waf_skip_body_path_prefixes: Tuple[str, ...]

    # --- Banlist ---
    ban_enabled: bool
    ban_window_sec: int
    ban_threshold: int
    ban_ttl_sec: int
    ban_strike_statuses: set[int]
    ban_strike_weight_waf: int
    ban_strike_weight_429: int
    ban_strike_weight_default: int

    @classmethod
    def from_env(cls) -> "WafBanConfig":
        return cls(
            waf_enabled=_env_bool("WAF_ENABLED", True),
            waf_block=_env_bool("WAF_BLOCK", True),
            waf_max_query_len=_env_int("WAF_MAX_QUERY_LEN", 2048),
            waf_max_header_len=_env_int("WAF_MAX_HEADER_LEN", 4096),
            waf_max_body_bytes=_env_int("WAF_MAX_BODY_BYTES", 4096),
            waf_skip_body_path_prefixes=(
                # free-text endpoints
                "/api/start",
                "/api/session/answer",
                "/api/evaluate",
                "/api/transcribe",
                "/api/parse_pdf",
            ),
            ban_enabled=_env_bool("BAN_ENABLED", True),
            ban_window_sec=_env_int("BAN_WINDOW_SEC", 300),
            ban_threshold=_env_int("BAN_THRESHOLD", 40),
            ban_ttl_sec=_env_int("BAN_TTL_SEC", 3600),
            ban_strike_statuses=_env_csv_int_set(
                "BAN_STRIKE_STATUSES", default=(401, 403, 404, 405, 429)
            ),
            ban_strike_weight_waf=_env_int("BAN_STRIKE_WEIGHT_WAF", 5),
            ban_strike_weight_429=_env_int("BAN_STRIKE_WEIGHT_429", 2),
            ban_strike_weight_default=_env_int("BAN_STRIKE_WEIGHT_DEFAULT", 1),
        )


def get_ip_from_request(request) -> str:
    """Best-effort client IP extraction.

    Assumes you are behind a reverse proxy that sets X-Forwarded-For.
    """
    xff = request.headers.get("x-forwarded-for")
    if xff:
        ip = xff.split(",")[0].strip()
        if ip:
            return ip
    if getattr(request, "client", None) and getattr(request.client, "host", None):
        return request.client.host
    return "0.0.0.0"


def ban_key_from_request(request, salt: str) -> str:
    """Returns a privacy-preserving ban key.

    We only hash the IP (not User-Agent) to make bans harder to evade.
    """
    ip = get_ip_from_request(request)
    raw = f"{ip}|{salt}|ban-v1".encode("utf-8", errors="ignore")
    return hashlib.sha256(raw).hexdigest()[:16]


def ban_key_for_request(request, salt: str) -> str:
    """Backward-compatible alias."""
    return ban_key_from_request(request, salt)



class BanDB:
    """SQLite-backed ban list.

    Stores ban_key only (hashed). Does not store raw IP.
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init_db(self) -> None:
        conn = self._connect()
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS ip_bans (
                    ban_key TEXT PRIMARY KEY,
                    reason TEXT,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL
                );
                """
            )
            conn.commit()
        finally:
            conn.close()

    def is_banned(self, ban_key: str, now_ts: Optional[int] = None) -> bool:
        now_ts = int(time.time()) if now_ts is None else int(now_ts)
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT expires_at FROM ip_bans WHERE ban_key = ?", (ban_key,)
            ).fetchone()
            if not row:
                return False
            if int(row["expires_at"]) > now_ts:
                return True
            # expired -> cleanup
            conn.execute("DELETE FROM ip_bans WHERE ban_key = ?", (ban_key,))
            conn.commit()
            return False
        finally:
            conn.close()

    def ban(self, ban_key: str, ttl_sec: int, reason: str = "aggressive") -> None:
        now_ts = int(time.time())
        exp = now_ts + int(ttl_sec)
        conn = self._connect()
        try:
            conn.execute(
                """
                INSERT INTO ip_bans (ban_key, reason, created_at, expires_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(ban_key)
                DO UPDATE SET reason=excluded.reason, created_at=excluded.created_at, expires_at=excluded.expires_at;
                """,
                (ban_key, reason[:200], now_ts, exp),
            )
            conn.commit()
        finally:
            conn.close()


class StrikeTracker:
    """In-memory strike tracker with a rolling window.

    We don't persist strikes to DB to keep it light. Only bans are persisted.
    """

    def __init__(self, cfg: WafBanConfig, ban_db: BanDB):
        self.cfg = cfg
        self.ban_db = ban_db
        # ban_key -> (window_start_ts, strikes)
        self._state: dict[str, Tuple[int, int]] = {}

    def add_strike(self, ban_key: str, weight: int = 1, reason: str = "strike") -> bool:
        """Adds a strike and returns True if a ban was applied."""

        if not self.cfg.ban_enabled:
            return False

        now_ts = int(time.time())
        window_start, strikes = self._state.get(ban_key, (now_ts, 0))

        if now_ts - window_start > self.cfg.ban_window_sec:
            window_start, strikes = now_ts, 0

        strikes += int(weight)
        self._state[ban_key] = (window_start, strikes)

        if strikes >= self.cfg.ban_threshold:
            self.ban_db.ban(ban_key, ttl_sec=self.cfg.ban_ttl_sec, reason=reason)
            # reset strikes after ban to reduce memory growth
            self._state.pop(ban_key, None)
            return True


        return False

    def get_strikes(self, ban_key: str) -> int:
        """Returns current strike score within the rolling window."""
        if not self.cfg.ban_enabled:
            return 0
        now_ts = int(time.time())
        window_start, strikes = self._state.get(ban_key, (now_ts, 0))
        if now_ts - window_start > self.cfg.ban_window_sec:
            return 0
        return int(strikes)





# -------- WAF patterns (conservative) --------

# URL / header scan patterns: these are almost never legitimate in a query string.
_URL_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"(?i)<\s*script"), "xss_script"),
    (re.compile(r"(?i)javascript:"), "xss_js"),
    (re.compile(r"(?i)\bunion\b\s+\bselect\b"), "sqli_union"),
    (re.compile(r"(?i)\bor\b\s+\d+=\d+"), "sqli_bool"),
    (re.compile(r"(?i)\bselect\b\s+.+\s+\bfrom\b"), "sqli_select"),
    (re.compile(r"(?i)\.\./"), "path_traversal"),
    (re.compile(r"%2e%2e%2f", re.I), "path_traversal_enc"),
    (re.compile(r"%00"), "null_byte"),
]

# Sensitive JSON endpoints (billing/admin/delete) can be body-inspected.
_BODY_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"(?i)<\s*script"), "xss_script"),
    (re.compile(r"(?i)javascript:"), "xss_js"),
    (re.compile(r"(?i)\bunion\b\s+\bselect\b"), "sqli_union"),
    (re.compile(r"(?i)\bselect\b\s+.+\s+\bfrom\b"), "sqli_select"),
]

_KNOWN_BOT_PATH_FRAGMENTS = (
    '/wp-admin',
    '/wp-login',
    'phpmyadmin',
    '/.env',
    '/.git',
    '/cgi-bin',
    'vendor/phpunit',
    '/actuator',
    'adminer.php',
)


def waf_should_read_body(request, cfg: WafBanConfig) -> bool:
    # Only inspect bodies for API calls with small JSON payloads
    path = request.url.path

    if any(path.startswith(p) for p in cfg.waf_skip_body_path_prefixes):
        return False

    ctype = request.headers.get("content-type", "")
    if ctype.startswith("multipart/form-data"):
        return False

    if ctype.startswith("application/json"):
        return True

    # For other content-types we avoid body inspection.
    return False


def _scan_text(text: str, patterns: Iterable[Tuple[re.Pattern, str]]) -> List[str]:
    reasons: List[str] = []
    for pat, tag in patterns:
        if pat.search(text):
            reasons.append(tag)
    return reasons


def waf_check(request, body_bytes: Optional[bytes], cfg: WafBanConfig) -> List[str]:
    """Return list of reasons if request looks suspicious."""

    if not cfg.waf_enabled:
        return []

    reasons: List[str] = []

    # 1) Path + query
    raw_qs = request.url.query or ""
    if len(raw_qs) > cfg.waf_max_query_len:
        reasons.append("query_too_long")
    raw_path_qs = request.url.path + ("?" + raw_qs if raw_qs else "")
    lp = request.url.path.lower()
    if any(frag in lp for frag in _KNOWN_BOT_PATH_FRAGMENTS):
        reasons.append('bot_probe')
    decoded_path_qs = urllib.parse.unquote_plus(raw_path_qs)
    reasons.extend(_scan_text(raw_path_qs, _URL_PATTERNS))
    if decoded_path_qs != raw_path_qs:
        reasons.extend(_scan_text(decoded_path_qs, _URL_PATTERNS))

    # 2) Some headers (cap length)
    # Avoid scanning cookies (can contain random opaque values).
    for k, v in request.headers.items():
        lk = k.lower()
        if lk in {"cookie", "authorization"}:
            continue
        if v and len(v) > cfg.waf_max_header_len:
            reasons.append(f"header_too_long:{lk}")
            continue
        if v:
            reasons.extend(_scan_text(v, _URL_PATTERNS))

    # 3) Body (only for safe-to-inspect endpoints)
    if body_bytes is not None and len(body_bytes) > 0:
        if len(body_bytes) > cfg.waf_max_body_bytes:
            # For JSON endpoints, huge body is unusual.
            reasons.append("body_too_large")
        else:
            # Only scan if it is valid-ish utf-8 JSON; otherwise ignore.
            try:
                txt = body_bytes.decode("utf-8", errors="ignore")
                # Normalize JSON to reduce false negatives
                try:
                    obj = json.loads(txt)
                    txt = json.dumps(obj, ensure_ascii=False)
                except Exception:
                    pass
                reasons.extend(_scan_text(txt, _BODY_PATTERNS))
            except Exception:
                pass

    # Deduplicate
    return sorted(set(reasons))


# --- Security Events (Admin Panel) -------------------------------------------


# ------------------------
# Request size limits (defensive guardrails)
# ------------------------

def body_limit_for_path(path: str) -> int:
    """Returns a hard cap for request body size (bytes) by endpoint.

    This is meant to stop obvious abuse early (huge JSON payloads, oversized uploads)
    before expensive parsing / OCR / model calls happen.
    """
    path = path or ""

    # Large upload endpoints
    if path.startswith("/api/parse_pdf"):
        pdf_mb = _env_int("PDF_MAX_MB", 12)
        return max(1, pdf_mb) * 1024 * 1024 + 1024

    if path.startswith("/api/transcribe"):
        audio_mb = _env_int("AUDIO_MAX_MB", 12)
        return max(1, audio_mb) * 1024 * 1024 + 1024

    # Billing / pro / admin should stay tiny
    if path.startswith("/api/billing/"):
        return _env_int("BILLING_MAX_BODY_BYTES", 32 * 1024)

    if path.startswith("/api/pro/"):
        return _env_int("PRO_MAX_BODY_BYTES", 32 * 1024)

    if path.startswith("/api/admin/"):
        return _env_int("ADMIN_MAX_BODY_BYTES", 32 * 1024)

    # Evaluate can be larger (answer + CV), but still bounded
    if path.startswith("/api/evaluate"):
        return _env_int("EVAL_MAX_BODY_BYTES", 256 * 1024)

    if path.startswith("/api/start"):
        return _env_int("START_MAX_BODY_BYTES", 64 * 1024)

    # General API default
    if path.startswith("/api/"):
        return _env_int("API_MAX_BODY_BYTES", 128 * 1024)

    # Non-API pages
    return _env_int("MAX_BODY_BYTES", 128 * 1024)


class SecurityEventDB:
    """Stores security-relevant events in SQLite for a simple admin panel.

    Notes:
    - We store *no raw IP*. Use ban_key (hashed) + client_id (hashed) for correlation.
    - Keep details small; this is not a full request logger.
    """

    def __init__(self, db_path: str, retention_days: int = 30):
        self.db_path = db_path
        self.retention_days = max(1, int(retention_days))
        self._init_db()
        self.prune()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path, check_same_thread=False, timeout=30)

    def _init_db(self) -> None:
        con = self._connect()
        try:
            cur = con.cursor()
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    ban_key TEXT,
                    client_id TEXT,
                    method TEXT,
                    path TEXT,
                    status INTEGER,
                    weight INTEGER,
                    ua TEXT,
                    details TEXT
                )
                """
            )
            cur.execute("CREATE INDEX IF NOT EXISTS idx_security_events_ts ON security_events(ts)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_security_events_type ON security_events(event_type)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_security_events_bankey ON security_events(ban_key)")
            con.commit()
        finally:
            con.close()

    def log(
        self,
        event_type: str,
        *,
        ban_key: str | None = None,
        client_id: str | None = None,
        method: str | None = None,
        path: str | None = None,
        status: int | None = None,
        weight: int | None = None,
        ua: str | None = None,
        details: dict | None = None,
    ) -> None:
        # Best-effort: never fail the request because logging failed.
        try:
            con = self._connect()
            try:
                cur = con.cursor()
                cur.execute(
                    """
                    INSERT INTO security_events
                        (ts, event_type, ban_key, client_id, method, path, status, weight, ua, details)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        int(time.time()),
                        event_type[:64],
                        (ban_key or "")[:128] or None,
                        (client_id or "")[:128] or None,
                        (method or "")[:16] or None,
                        (path or "")[:256] or None,
                        status,
                        weight,
                        ((ua or "")[:200] or None),
                        json.dumps(details or {}, ensure_ascii=False)[:2000],
                    ),
                )
                con.commit()
            finally:
                con.close()
        except Exception:
            return

    def recent(self, limit: int = 200) -> list[dict]:
        limit = max(1, min(int(limit), 1000))
        con = self._connect()
        try:
            cur = con.cursor()
            cur.execute(
                """
                SELECT ts, event_type, ban_key, client_id, method, path, status, weight, ua, details
                FROM security_events
                ORDER BY ts DESC, id DESC
                LIMIT ?
                """,
                (limit,),
            )
            out: list[dict] = []
            for row in cur.fetchall():
                ts, event_type, ban_key, client_id, method, path, status, weight, ua, details = row
                try:
                    details_obj = json.loads(details) if details else {}
                except Exception:
                    details_obj = {"raw": details}
                out.append(
                    {
                        "ts": ts,
                        "event_type": event_type,
                        "ban_key": ban_key,
                        "client_id": client_id,
                        "method": method,
                        "path": path,
                        "status": status,
                        "weight": weight,
                        "ua": ua,
                        "details": details_obj,
                    }
                )
            return out
        finally:
            con.close()

    def summary(self, minutes: int = 60) -> dict:
        minutes = max(1, min(int(minutes), 60 * 24 * 30))  # up to 30 days
        since_ts = int(time.time()) - (minutes * 60)
        con = self._connect()
        try:
            cur = con.cursor()

            cur.execute(
                """
                SELECT event_type, COUNT(*) as c
                FROM security_events
                WHERE ts >= ?
                GROUP BY event_type
                ORDER BY c DESC
                """,
                (since_ts,),
            )
            by_type = [{"event_type": r[0], "count": r[1]} for r in cur.fetchall()]

            cur.execute(
                """
                SELECT path, COUNT(*) as c
                FROM security_events
                WHERE ts >= ? AND path IS NOT NULL
                GROUP BY path
                ORDER BY c DESC
                LIMIT 10
                """,
                (since_ts,),
            )
            top_paths = [{"path": r[0], "count": r[1]} for r in cur.fetchall()]

            cur.execute(
                """
                SELECT ban_key, COUNT(*) as c
                FROM security_events
                WHERE ts >= ? AND ban_key IS NOT NULL
                GROUP BY ban_key
                ORDER BY c DESC
                LIMIT 10
                """,
                (since_ts,),
            )
            top_sources = [{"ban_key": r[0], "count": r[1]} for r in cur.fetchall()]

            return {
                "minutes": minutes,
                "since_ts": since_ts,
                "by_type": by_type,
                "top_paths": top_paths,
                "top_sources": top_sources,
            }
        finally:
            con.close()



    def count_since(self, event_types: Sequence[str], since_ts: int) -> int:
        """Count events since `since_ts` for the given types (best-effort)."""
        try:
            et = [str(x) for x in (event_types or []) if str(x)]
            if not et:
                return 0
            since_ts = int(since_ts)
            con = self._connect()
            try:
                cur = con.cursor()
                placeholders = ",".join(["?"] * len(et))
                cur.execute(
                    f"SELECT COUNT(*) FROM security_events WHERE ts >= ? AND event_type IN ({placeholders})",
                    (since_ts, *et),
                )
                row = cur.fetchone()
                return int(row[0] if row else 0)
            finally:
                con.close()
        except Exception:
            return 0

    def count_distinct_ban_keys_since(self, event_types: Sequence[str], since_ts: int) -> int:
        """Count distinct ban_key sources since `since_ts` for the given types."""
        try:
            et = [str(x) for x in (event_types or []) if str(x)]
            if not et:
                return 0
            since_ts = int(since_ts)
            con = self._connect()
            try:
                cur = con.cursor()
                placeholders = ",".join(["?"] * len(et))
                cur.execute(
                    f"""SELECT COUNT(DISTINCT ban_key)
                        FROM security_events
                        WHERE ts >= ?
                          AND ban_key IS NOT NULL
                          AND event_type IN ({placeholders})
                    """,
                    (since_ts, *et),
                )
                row = cur.fetchone()
                return int(row[0] if row else 0)
            finally:
                con.close()
        except Exception:
            return 0
    def prune(self) -> None:
        cutoff = int(time.time()) - int(self.retention_days * 86400)
        con = self._connect()
        try:
            cur = con.cursor()
            cur.execute("DELETE FROM security_events WHERE ts < ?", (cutoff,))
            con.commit()
        finally:
            con.close()
