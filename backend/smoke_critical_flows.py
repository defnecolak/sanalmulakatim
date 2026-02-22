#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Critical-flow smoke tests (Recovery / Delete / Pro) for Sanal Mülakatım.

This script is meant to be run *by operators* (you) during production migrations,
post-deploy checks, or incident triage.

Design goals
------------
- Test the *real* HTTP endpoints (health/usage/recovery consume/delete confirm)
- Avoid sending real emails (no SMTP required)
- Keep things safe: create small, tagged test records and clean up after.

How it works
------------
1) Inserts a temporary pro token into the DB (Postgres or SQLite).
2) Links it to a synthetic email hash.
3) Creates a one-time recovery link (direct DB insert) and consumes it via HTTP.
4) Creates a one-time delete link (direct DB insert) and confirms it via HTTP.
5) Verifies Pro token still works (privacy delete should not revoke pro access).
6) Deletes the temporary pro token from the DB.

Important
---------
- Requires DB access (DATABASE_URL or usage.db path).
- Requires the app to be running (base URL).

Usage
-----
  python backend/smoke_critical_flows.py --base-url http://localhost:5555

Exit codes
----------
0 = OK
10+ = failure at some step
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sqlite3
import sys
import time
import uuid
from dataclasses import dataclass
from typing import Any, Optional

import requests


def _env_str(name: str, default: str = "") -> str:
    v = os.environ.get(name)
    if v is None or v.strip() == "":
        return default
    return v.strip()


def _now() -> int:
    return int(time.time())


def _sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _email_hash(email: str) -> str:
    email = (email or "").strip().lower()
    salt = (_env_str("EMAIL_HASH_SALT", "") or "").strip()
    return _sha256_hex((salt + "|" + email).encode("utf-8"))


def _recovery_hash(raw: str) -> str:
    raw = (raw or "").strip()
    secret = (_env_str("RECOVERY_TOKEN_SECRET", "") or _env_str("SESSION_SECRET", "")).strip()
    return _sha256_hex((secret + "|" + raw).encode("utf-8"))


def _delete_hash(raw: str) -> str:
    raw = (raw or "").strip()
    secret = (_env_str("DELETE_TOKEN_SECRET", "") or _env_str("SESSION_SECRET", "")).strip()
    return _sha256_hex((secret + "|" + raw).encode("utf-8"))


def _pg_url_from_env() -> str:
    url = (_env_str("DATABASE_URL", "") or "").strip()
    if url:
        return url
    if (_env_str("DB_ENGINE", "") or "").strip().lower() != "postgres":
        return ""
    host = _env_str("PG_HOST", "postgres") or "postgres"
    port = _env_str("PG_PORT", "5432") or "5432"
    user = _env_str("PG_USER", "sanal") or "sanal"
    pw = _env_str("PG_PASSWORD", "")
    db = _env_str("PG_DB", "sanal_mulakatim") or "sanal_mulakatim"
    if pw:
        from urllib.parse import quote

        return f"postgresql://{user}:{quote(pw, safe='')}@{host}:{port}/{db}"
    return f"postgresql://{user}@{host}:{port}/{db}"


@dataclass
class DB:
    engine: str
    pg_conn: Any = None
    sqlite_conn: Optional[sqlite3.Connection] = None

    def close(self) -> None:
        try:
            if self.pg_conn is not None:
                self.pg_conn.close()
        except Exception:
            pass
        try:
            if self.sqlite_conn is not None:
                self.sqlite_conn.close()
        except Exception:
            pass

    def exec(self, sql: str, params: tuple = ()) -> None:
        if self.engine == "postgres":
            with self.pg_conn.cursor() as cur:
                cur.execute(sql, params)
            self.pg_conn.commit()
        else:
            cur = self.sqlite_conn.cursor()
            cur.execute(sql, params)
            self.sqlite_conn.commit()

    def fetchone(self, sql: str, params: tuple = ()) -> Optional[tuple]:
        if self.engine == "postgres":
            with self.pg_conn.cursor() as cur:
                cur.execute(sql, params)
                row = cur.fetchone()
            return row
        cur = self.sqlite_conn.cursor()
        cur.execute(sql, params)
        row = cur.fetchone()
        return row


def _connect_db() -> DB:
    pg_url = _pg_url_from_env()
    if pg_url:
        try:
            import psycopg
        except Exception as e:
            raise SystemExit(
                "psycopg yok. Postgres smoke için: pip install 'psycopg[binary]'"
            ) from e
        conn = psycopg.connect(pg_url, connect_timeout=8)
        return DB(engine="postgres", pg_conn=conn)

    # fallback sqlite
    path = _env_str("USAGE_DB_PATH", "backend/data/usage.db")
    path = os.path.abspath(path)
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    return DB(engine="sqlite", sqlite_conn=con)


def _http_json(method: str, url: str, **kwargs) -> tuple[int, Any]:
    r = requests.request(method, url, timeout=15, **kwargs)
    try:
        return r.status_code, r.json()
    except Exception:
        return r.status_code, r.text


def main() -> int:
    ap = argparse.ArgumentParser(description="Critical-flow smoke tests")
    ap.add_argument(
        "--base-url",
        default=_env_str("PUBLIC_BASE_URL", "http://localhost:5555").rstrip("/"),
        help="Base URL for the running app (default: PUBLIC_BASE_URL)",
    )
    ap.add_argument(
        "--email",
        default="smoke@sanalmulakatim.com",
        help="Synthetic email used only for smoke test DB links",
    )
    ap.add_argument(
        "--keep-pro-token",
        action="store_true",
        help="Do not delete the temporary pro token after test",
    )
    args = ap.parse_args()

    base = (args.base_url or "").rstrip("/")
    if not base.startswith("http"):
        print("base-url must start with http(s)")
        return 11

    # 0) Health
    print("[1/6] healthz…")
    st, js = _http_json("GET", f"{base}/api/healthz")
    if st != 200:
        print("FAIL healthz", st, js)
        return 12

    print("[2/6] usage (FREE)…")
    st, js = _http_json("GET", f"{base}/api/usage")
    if st != 200 or not isinstance(js, dict) or "plan" not in js:
        print("FAIL usage", st, js)
        return 13

    # DB connect
    db = _connect_db()
    try:
        email = (args.email or "").strip().lower()
        eh = _email_hash(email)

        # Create a temp pro token
        pro_token = "smoke_" + uuid.uuid4().hex
        now = _now()
        print(f"[3/6] create temporary pro token… ({db.engine})")

        if db.engine == "postgres":
            db.exec(
                "INSERT INTO pro_tokens(token, created_at, provider, provider_ref, stripe_session_id, client_id) "
                "VALUES (%s,%s,%s,%s,%s,%s) ON CONFLICT (token) DO UPDATE SET created_at=EXCLUDED.created_at",
                (pro_token, now, "smoke", "smoke", None, "smoke"),
            )
            db.exec(
                "INSERT INTO email_token_links(email_hash, token, created_at) VALUES (%s,%s,%s) "
                "ON CONFLICT (email_hash, token) DO UPDATE SET created_at=EXCLUDED.created_at",
                (eh, pro_token, now),
            )
        else:
            db.exec(
                "INSERT OR REPLACE INTO pro_tokens(token, created_at, provider, provider_ref, stripe_session_id, client_id) VALUES(?,?,?,?,?,?)",
                (pro_token, now, "smoke", "smoke", None, "smoke"),
            )
            db.exec(
                "INSERT OR IGNORE INTO email_token_links(email_hash, token, created_at) VALUES(?,?,?)",
                (eh, pro_token, now),
            )

        print("[4/6] verify PRO plan via /api/usage…")
        st, js = _http_json("GET", f"{base}/api/usage", headers={"x-pro-token": pro_token})
        if st != 200 or not isinstance(js, dict) or js.get("plan") != "PRO":
            print("FAIL pro usage", st, js)
            return 14

        # Recovery flow: insert a recovery link token and consume via HTTP
        print("[5/6] recovery consume…")
        raw_rec = "ml_" + uuid.uuid4().hex + uuid.uuid4().hex[:8]
        rec_hash = _recovery_hash(raw_rec)
        exp = now + 15 * 60
        if db.engine == "postgres":
            db.exec(
                "INSERT INTO recovery_links(token_hash, email_hash, created_at, expires_at, consumed_at) "
                "VALUES (%s,%s,%s,%s,NULL) ON CONFLICT (token_hash) DO UPDATE SET expires_at=EXCLUDED.expires_at, consumed_at=NULL",
                (rec_hash, eh, now, exp),
            )
        else:
            db.exec(
                "INSERT OR REPLACE INTO recovery_links(token_hash, email_hash, created_at, expires_at, consumed_at) VALUES(?,?,?,?,NULL)",
                (rec_hash, eh, now, exp),
            )

        st, js = _http_json("POST", f"{base}/api/pro/recovery/consume", json={"token": raw_rec})
        if st != 200 or not isinstance(js, dict) or pro_token not in (js.get("tokens") or []):
            print("FAIL recovery consume", st, js)
            return 15

        # Privacy delete flow
        print("[6/6] privacy delete confirm…")
        raw_del = "dl_" + uuid.uuid4().hex + uuid.uuid4().hex[:8]
        del_hash = _delete_hash(raw_del)
        exp2 = now + 30 * 60

        if db.engine == "postgres":
            db.exec("DELETE FROM delete_links WHERE email_hash=%s", (eh,))
            db.exec(
                "INSERT INTO delete_links(token_hash, email_hash, created_at, expires_at, consumed_at) "
                "VALUES (%s,%s,%s,%s,NULL) ON CONFLICT (token_hash) DO UPDATE SET expires_at=EXCLUDED.expires_at, consumed_at=NULL",
                (del_hash, eh, now, exp2),
            )
        else:
            db.exec("DELETE FROM delete_links WHERE email_hash=?", (eh,))
            db.exec(
                "INSERT OR REPLACE INTO delete_links(token_hash, email_hash, created_at, expires_at, consumed_at) VALUES(?,?,?,?,NULL)",
                (del_hash, eh, now, exp2),
            )

        st, js = _http_json("POST", f"{base}/api/privacy/delete/confirm", json={"token": raw_del})
        if st != 200 or not isinstance(js, dict) or not js.get("ok"):
            print("FAIL delete confirm", st, js)
            return 16

        # Pro token should still be valid (delete doesn't revoke Pro)
        st, js2 = _http_json("GET", f"{base}/api/usage", headers={"x-pro-token": pro_token})
        if st != 200 or not isinstance(js2, dict) or js2.get("plan") != "PRO":
            print("FAIL pro still valid", st, js2)
            return 17

        # Cleanup
        if not args.keep_pro_token:
            print("cleanup: delete temporary pro token…")
            if db.engine == "postgres":
                db.exec("DELETE FROM pro_tokens WHERE token=%s", (pro_token,))
            else:
                db.exec("DELETE FROM pro_tokens WHERE token=?", (pro_token,))

        print("OK: critical flows passed.")
        return 0

    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
