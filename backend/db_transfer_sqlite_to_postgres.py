#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""One-time data transfer: SQLite -> Postgres.

Why this exists
---------------
The app started with SQLite (backend/data/usage.db). When moving to Postgres
for multi-instance / blue-green deploys, you may want to carry over:

- FREE usage counters (total trials)
- Pro tokens and payment orders
- Recovery/delete links
- Ban list + security events (admin panel history)

This script is intentionally conservative:
- By default it uses UPSERT (ON CONFLICT) and does NOT truncate tables.
- security_events are only imported if the destination table is empty
  (to avoid accidental duplicates). Use --truncate to force a clean import.

New in this version
-------------------
- Row-count verification (SQLite vs Postgres) after transfer
- Optional SQLite archival (consistent snapshot using sqlite backup API)
- Optional read-only switch for the old SQLite file (helps prevent accidental writes)

Usage (recommended)
-------------------
1) Stop the app (or switch traffic away) to avoid writes during copy.
2) Ensure Postgres is reachable.
3) Run:

  python backend/db_transfer_sqlite_to_postgres.py \
    --sqlite backend/data/usage.db \
    --migrate \
    --strict-counts \
    --archive-sqlite \
    --set-readonly

Environment:
  - If --pg-url is not provided, DATABASE_URL / PG_* / DB_ENGINE=postgres are used.

Tip: If you're running in Docker, execute this inside the app container so
it can reach the 'postgres' service on the internal network.
"""

from __future__ import annotations

import argparse
import os
import sqlite3
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


def _pg_url_from_env() -> str:
    url = (os.environ.get("DATABASE_URL") or "").strip()
    if url:
        return url
    engine = (os.environ.get("DB_ENGINE") or "").strip().lower()
    if engine != "postgres":
        return ""
    host = (os.environ.get("PG_HOST") or "postgres").strip() or "postgres"
    port = (os.environ.get("PG_PORT") or "5432").strip() or "5432"
    user = (os.environ.get("PG_USER") or "sanal").strip() or "sanal"
    password = (os.environ.get("PG_PASSWORD") or "").strip()
    db = (os.environ.get("PG_DB") or "sanal_mulakatim").strip() or "sanal_mulakatim"
    if password:
        from urllib.parse import quote

        pw = quote(password, safe="")
        return f"postgresql://{user}:{pw}@{host}:{port}/{db}"
    return f"postgresql://{user}@{host}:{port}/{db}"


def _sqlite_connect(path: str) -> sqlite3.Connection:
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    return con


def _sqlite_table_exists(con: sqlite3.Connection, table: str) -> bool:
    row = con.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone()
    return bool(row)


def _sqlite_columns(con: sqlite3.Connection, table: str) -> set[str]:
    rows = con.execute(f"PRAGMA table_info({table});").fetchall()
    return {r[1] for r in rows}


def _sqlite_count(con: sqlite3.Connection, table: str) -> int:
    return int(con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])


def _iter_sqlite_rows(con: sqlite3.Connection, table: str) -> Iterable[Dict[str, Any]]:
    cur = con.execute(f"SELECT * FROM {table};")
    for row in cur.fetchall():
        yield dict(row)


def _maybe_run_migrations(pg_url: str) -> None:
    """Run Postgres migrations idempotently."""
    here = Path(__file__).resolve().parent
    mig_dir = here / "migrations" / "postgres"
    cmd = [
        sys.executable,
        str(here / "db_migrate.py"),
        "--engine",
        "postgres",
        "--url",
        pg_url,
        "--dir",
        str(mig_dir),
    ]
    subprocess.check_call(cmd)


def _pg_connect(pg_url: str):
    try:
        import psycopg
    except Exception as e:  # pragma: no cover
        raise SystemExit(
            "psycopg kurulu değil. Postgres transfer için: pip install 'psycopg[binary]'"
        ) from e
    return psycopg.connect(pg_url, connect_timeout=8)


def _pg_count(conn, table: str) -> int:
    with conn.cursor() as cur:
        cur.execute(f"SELECT COUNT(*) FROM {table}")
        return int(cur.fetchone()[0])


def _pg_truncate(conn, tables: Sequence[str]) -> None:
    with conn.cursor() as cur:
        for t in tables:
            cur.execute(f"TRUNCATE TABLE {t} RESTART IDENTITY")
    conn.commit()


def _batch(iterable: Iterable[Tuple[Any, ...]], size: int = 500) -> Iterable[List[Tuple[Any, ...]]]:
    buf: List[Tuple[Any, ...]] = []
    for item in iterable:
        buf.append(item)
        if len(buf) >= size:
            yield buf
            buf = []
    if buf:
        yield buf


def _archive_sqlite_snapshot(src_path: str, archive_dir: str) -> str:
    """Create a consistent snapshot of the SQLite DB using sqlite backup API."""
    src = Path(src_path)
    ad = Path(archive_dir)
    ad.mkdir(parents=True, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    dst = ad / f"{src.name}.{ts}.bak"

    # Consistent copy (safe even if WAL mode is used).
    with sqlite3.connect(src_path) as src_con:
        with sqlite3.connect(str(dst)) as dst_con:
            src_con.backup(dst_con)

    return str(dst)


def _set_readonly(path: str) -> None:
    """Best-effort: make sqlite db (and wal/shm if present) read-only."""
    try:
        os.chmod(path, 0o444)
    except Exception:
        pass
    for suf in ("-wal", "-shm"):
        p = path + suf
        if os.path.exists(p):
            try:
                os.chmod(p, 0o444)
            except Exception:
                pass


def _print_counts_table(rows: List[Tuple[str, int, int, bool, str]]) -> None:
    # Simple aligned table
    name_w = max(10, max(len(r[0]) for r in rows) if rows else 10)
    print("\nRow count verification:")
    print(f"{'table':<{name_w}}  sqlite  postgres  ok  note")
    print(f"{'-'*name_w}  -----  -------  --  ----")
    for t, s, p, ok, note in rows:
        ok_s = "OK" if ok else "NO"
        print(f"{t:<{name_w}}  {s:>5}  {p:>7}  {ok_s:<2}  {note}")


def main() -> int:
    p = argparse.ArgumentParser(description="SQLite -> Postgres one-time transfer")
    p.add_argument(
        "--sqlite",
        default=os.environ.get("USAGE_DB_PATH") or "backend/data/usage.db",
        help="Path to SQLite usage.db (source)",
    )
    p.add_argument(
        "--pg-url",
        default=os.environ.get("DATABASE_URL") or "",
        help="Postgres URL. If empty, uses DATABASE_URL or PG_* env.",
    )
    p.add_argument(
        "--migrate",
        action="store_true",
        help="Run Postgres migrations before transfer (recommended)",
    )
    p.add_argument(
        "--truncate",
        action="store_true",
        help="TRUNCATE destination tables before import (dangerous; but avoids duplicates)",
    )
    p.add_argument(
        "--skip-security-events",
        action="store_true",
        help="Skip importing security_events (admin panel history)",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Only print what would be transferred (no Postgres needed)",
    )

    # Verification / post-actions
    p.add_argument(
        "--no-verify-counts",
        action="store_true",
        help="Disable row-count verification (SQLite vs Postgres)",
    )
    p.add_argument(
        "--strict-counts",
        action="store_true",
        help="Fail with non-zero exit code if count verification fails",
    )
    p.add_argument(
        "--archive-sqlite",
        action="store_true",
        help="Create an archived snapshot copy of the SQLite DB after transfer",
    )
    p.add_argument(
        "--archive-dir",
        default=os.environ.get("SQLITE_ARCHIVE_DIR") or "deploy/backups",
        help="Directory to write the SQLite archive snapshot (default: deploy/backups)",
    )
    p.add_argument(
        "--set-readonly",
        action="store_true",
        help="Make the SQLite source DB read-only after transfer (best-effort)",
    )

    args = p.parse_args()

    sqlite_path = str(Path(args.sqlite).expanduser())
    if not os.path.exists(sqlite_path):
        print(f"SQLite file not found: {sqlite_path}")
        return 2

    pg_url = (args.pg_url or "").strip() or _pg_url_from_env()

    wanted_tables = [
        "usage_daily",
        "usage_total",
        "pro_tokens",
        "payment_orders",
        "email_token_links",
        "recovery_links",
        "delete_links",
        "ip_bans",
        "security_events",
    ]

    if args.dry_run:
        con = _sqlite_connect(sqlite_path)
        try:
            print("DRY RUN (SQLite -> Postgres)")
            print(f"Source: {sqlite_path}")
            if pg_url:
                print("Destination: (pg-url provided via env/args)")
            else:
                print("Destination: (pg-url NOT provided)")
            for t in wanted_tables:
                if not _sqlite_table_exists(con, t):
                    continue
                n = _sqlite_count(con, t)
                print(f"- {t}: {n} rows")
            print("Done.")
            return 0
        finally:
            con.close()

    if not pg_url:
        print(
            "Postgres URL missing. Provide --pg-url or set DATABASE_URL/PG_* with DB_ENGINE=postgres"
        )
        return 2

    # 1) Optional migrations
    if args.migrate:
        print("Running Postgres migrations (idempotent)…")
        _maybe_run_migrations(pg_url)

    # 2) Connect
    sqlite_con = _sqlite_connect(sqlite_path)
    pg_conn = _pg_connect(pg_url)
    try:
        dest_tables = list(wanted_tables)

        if args.truncate:
            print("TRUNCATE destination tables…")
            _pg_truncate(pg_conn, [t for t in dest_tables if t != "schema_migrations"])

        def import_upsert(
            table: str,
            expected_cols: Sequence[str],
            conflict_target: str,
            update_cols: Sequence[str],
        ) -> int:
            if not _sqlite_table_exists(sqlite_con, table):
                return 0
            src_cols = _sqlite_columns(sqlite_con, table)
            cols = list(expected_cols)
            placeholders = ",".join(["%s"] * len(cols))
            col_list = ",".join(cols)
            set_list = ",".join([f"{c}=EXCLUDED.{c}" for c in update_cols])
            sql = (
                f"INSERT INTO {table} ({col_list}) VALUES ({placeholders}) "
                f"ON CONFLICT {conflict_target} DO UPDATE SET {set_list}"
            )

            def rows() -> Iterable[Tuple[Any, ...]]:
                for r in _iter_sqlite_rows(sqlite_con, table):
                    yield tuple(r.get(c) if c in src_cols else None for c in cols)

            total = 0
            with pg_conn.cursor() as cur:
                for chunk in _batch(rows(), size=500):
                    cur.executemany(sql, chunk)
                    total += len(chunk)
            pg_conn.commit()
            return total

        print("Importing usage_daily…")
        n1 = import_upsert(
            "usage_daily",
            ["client_id", "day", "key", "count"],
            "(client_id, day, key)",
            ["count"],
        )

        print("Importing usage_total…")
        n2 = import_upsert(
            "usage_total",
            ["client_id", "key", "count"],
            "(client_id, key)",
            ["count"],
        )

        print("Importing pro_tokens…")
        n3 = import_upsert(
            "pro_tokens",
            ["token", "created_at", "provider", "provider_ref", "stripe_session_id", "client_id"],
            "(token)",
            ["created_at", "provider", "provider_ref", "stripe_session_id", "client_id"],
        )

        print("Importing payment_orders…")
        n4 = import_upsert(
            "payment_orders",
            [
                "order_id",
                "provider",
                "client_id",
                "email",
                "created_at",
                "updated_at",
                "status",
                "email_hash",
                "provider_token",
                "provider_payment_id",
                "last_error",
                "raw_response",
            ],
            "(order_id)",
            [
                "provider",
                "client_id",
                "email",
                "created_at",
                "updated_at",
                "status",
                "email_hash",
                "provider_token",
                "provider_payment_id",
                "last_error",
                "raw_response",
            ],
        )

        print("Importing email_token_links…")
        n5 = import_upsert(
            "email_token_links",
            ["email_hash", "token", "created_at"],
            "(email_hash, token)",
            ["created_at"],
        )

        print("Importing recovery_links…")
        n6 = import_upsert(
            "recovery_links",
            ["token_hash", "email_hash", "created_at", "expires_at", "consumed_at"],
            "(token_hash)",
            ["email_hash", "created_at", "expires_at", "consumed_at"],
        )

        print("Importing delete_links…")
        n7 = import_upsert(
            "delete_links",
            ["token_hash", "email_hash", "created_at", "expires_at", "consumed_at"],
            "(token_hash)",
            ["email_hash", "created_at", "expires_at", "consumed_at"],
        )

        print("Importing ip_bans…")
        n8 = import_upsert(
            "ip_bans",
            ["ban_key", "reason", "created_at", "expires_at"],
            "(ban_key)",
            ["reason", "created_at", "expires_at"],
        )

        n9 = 0
        imported_security_events = False
        if args.skip_security_events:
            print("Skipping security_events (per flag)…")
        else:
            if _sqlite_table_exists(sqlite_con, "security_events"):
                dst_count = _pg_count(pg_conn, "security_events")
                if dst_count > 0 and (not args.truncate):
                    print(
                        f"Skipping security_events because destination has {dst_count} rows. "
                        "Use --truncate to force a clean import or --skip-security-events to skip explicitly."
                    )
                else:
                    print("Importing security_events…")
                    src_cols = _sqlite_columns(sqlite_con, "security_events")
                    cols = [
                        "ts",
                        "event_type",
                        "ban_key",
                        "client_id",
                        "method",
                        "path",
                        "status",
                        "weight",
                        "ua",
                        "details",
                    ]
                    placeholders = ",".join(["%s"] * len(cols))
                    sql = f"INSERT INTO security_events ({','.join(cols)}) VALUES ({placeholders})"

                    def rows() -> Iterable[Tuple[Any, ...]]:
                        for r in _iter_sqlite_rows(sqlite_con, "security_events"):
                            yield tuple(r.get(c) if c in src_cols else None for c in cols)

                    with pg_conn.cursor() as cur:
                        for chunk in _batch(rows(), size=500):
                            cur.executemany(sql, chunk)
                            n9 += len(chunk)
                    pg_conn.commit()
                    imported_security_events = True

        print("\nTransfer summary:")
        print(f"- usage_daily:       {n1}")
        print(f"- usage_total:       {n2}")
        print(f"- pro_tokens:        {n3}")
        print(f"- payment_orders:    {n4}")
        print(f"- email_token_links: {n5}")
        print(f"- recovery_links:    {n6}")
        print(f"- delete_links:      {n7}")
        print(f"- ip_bans:           {n8}")
        print(f"- security_events:   {n9}")

        # 3) Row count verification
        if not args.no_verify_counts:
            rows: List[Tuple[str, int, int, bool, str]] = []
            ok_all = True

            for t in wanted_tables:
                if not _sqlite_table_exists(sqlite_con, t):
                    continue
                if t == "security_events" and (args.skip_security_events or (not imported_security_events)):
                    # If we didn't import, don't enforce counts.
                    s = _sqlite_count(sqlite_con, t)
                    try:
                        p_cnt = _pg_count(pg_conn, t)
                    except Exception:
                        p_cnt = 0
                    rows.append((t, s, p_cnt, True, "SKIP (not imported)"))
                    continue

                s = _sqlite_count(sqlite_con, t)
                p_cnt = _pg_count(pg_conn, t)

                if args.truncate:
                    ok = (p_cnt == s)
                    note = "expect equal (truncate)"
                else:
                    ok = (p_cnt >= s)
                    note = "expect >= (upsert)"

                if not ok:
                    ok_all = False
                rows.append((t, s, p_cnt, ok, note))

            if rows:
                _print_counts_table(rows)
                if ok_all:
                    print("Counts OK.")
                else:
                    print("Count verification FAILED (see table above).")

            if (not ok_all) and args.strict_counts:
                return 3

        # 4) Optional archive snapshot
        if args.archive_sqlite:
            # Resolve archive dir relative to repo root if a relative path is given.
            ad = args.archive_dir
            if not os.path.isabs(ad):
                # script is in backend/; repo root is one level up
                repo_root = str(Path(__file__).resolve().parent.parent)
                ad = str(Path(repo_root) / ad)
            try:
                dst = _archive_sqlite_snapshot(sqlite_path, ad)
                print(f"SQLite archived snapshot created: {dst}")
            except Exception as e:
                print(f"WARNING: SQLite archive snapshot failed: {type(e).__name__}: {e}")
                if args.strict_counts:
                    # Keep strict-mode harsh: archival is part of the hardened flow.
                    return 4

        # 5) Optional read-only
        if args.set_readonly:
            _set_readonly(sqlite_path)
            print("SQLite source DB set to read-only (best-effort).")

        print("Done.")
        return 0

    finally:
        try:
            sqlite_con.close()
        except Exception:
            pass
        try:
            pg_conn.close()
        except Exception:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
