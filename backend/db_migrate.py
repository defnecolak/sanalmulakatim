#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Lightweight SQL migration runner (SQLite + Postgres).

Why not Alembic?
- This project started as an MVP.
- For small schemas, sequential .sql migrations are often enough.
- You can still move to Alembic later if/when schema evolution grows.

Usage (SQLite):
  python db_migrate.py --engine sqlite --db backend/data/usage.db

Usage (Postgres):
  python db_migrate.py --engine postgres --url "$DATABASE_URL"

Notes:
- For Postgres, each migration file should be reasonably simple.
  (Prefer 1 statement per file; if you have multiple, separate with ';'.)
- For Postgres, we take an advisory lock to avoid concurrent migrations.
"""

from __future__ import annotations

import argparse
import os
import time
from pathlib import Path


def _guess_engine(engine: str, url: str) -> str:
    e = (engine or "").strip().lower()
    if e and e != "auto":
        return e
    u = (url or "").strip().lower()
    if u.startswith("postgres://") or u.startswith("postgresql://"):
        return "postgres"
    return "sqlite"


# ----------------------
# SQLite
# ----------------------

def _sqlite_connect(path: str):
    import sqlite3

    conn = sqlite3.connect(path)
    return conn


def _sqlite_ensure_schema_migrations(conn) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations(
          id TEXT PRIMARY KEY,
          applied_at INTEGER NOT NULL
        );
        """
    )
    conn.commit()


def _sqlite_applied_set(conn) -> set[str]:
    rows = conn.execute("SELECT id FROM schema_migrations").fetchall()
    return {r[0] for r in rows}


def _sqlite_apply_one(conn, mig_id: str, sql: str) -> None:
    cur = conn.cursor()
    cur.executescript(sql)
    cur.execute(
        "INSERT INTO schema_migrations(id, applied_at) VALUES (?, ?)",
        (mig_id, int(time.time())),
    )
    conn.commit()


# ----------------------
# Postgres
# ----------------------

def _pg_connect(url: str):
    try:
        import psycopg
    except Exception as e:  # pragma: no cover
        raise SystemExit(
            "psycopg kurulmamış. Postgres migration için: pip install 'psycopg[binary]'"
        ) from e

    return psycopg.connect(url, connect_timeout=8)


def _pg_split_sql(sql: str) -> list[str]:
    """Very small SQL splitter.

    Good enough for our migration style (mostly CREATE TABLE/INDEX, ALTER TABLE).
    Avoids splitting on comment-only lines.
    """
    lines: list[str] = []
    for ln in (sql or "").splitlines():
        s = ln.strip()
        if s.startswith("--"):
            continue
        lines.append(ln)
    cleaned = "\n".join(lines)
    parts = [p.strip() for p in cleaned.split(";")]
    return [p + ";" for p in parts if p.strip()]


def _pg_ensure_schema_migrations(conn) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations(
              id TEXT PRIMARY KEY,
              applied_at BIGINT NOT NULL
            );
            """
        )
    conn.commit()


def _pg_applied_set(conn) -> set[str]:
    with conn.cursor() as cur:
        cur.execute("SELECT id FROM schema_migrations")
        rows = cur.fetchall()
    return {r[0] for r in rows}


def _pg_apply_one(conn, mig_id: str, sql: str) -> None:
    stmts = _pg_split_sql(sql)
    with conn.cursor() as cur:
        for st in stmts:
            cur.execute(st)
        cur.execute(
            "INSERT INTO schema_migrations(id, applied_at) VALUES (%s, %s)",
            (mig_id, int(time.time())),
        )
    conn.commit()


def _pg_advisory_lock(conn) -> None:
    # A fixed 64-bit key. Keeps multi-instance deploys from racing.
    with conn.cursor() as cur:
        cur.execute("SELECT pg_advisory_lock(99112233)")


def _pg_advisory_unlock(conn) -> None:
    with conn.cursor() as cur:
        cur.execute("SELECT pg_advisory_unlock(99112233)")


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--engine", default=os.environ.get("DB_ENGINE", "auto"))
    p.add_argument(
        "--db",
        default=os.environ.get("USAGE_DB_PATH", "backend/data/usage.db"),
        help="SQLite path",
    )
    p.add_argument(
        "--url",
        default=os.environ.get("DATABASE_URL", ""),
        help="Postgres connection URL",
    )
    p.add_argument("--dir", default="", help="Migration directory")
    args = p.parse_args()

    engine = _guess_engine(args.engine, args.url)

    if engine == "postgres":
        # Allow building URL from parts (PG_*) if DATABASE_URL isn't provided.
        url = (args.url or "").strip()
        if not url:
            host = (os.environ.get("PG_HOST") or "postgres").strip() or "postgres"
            port = (os.environ.get("PG_PORT") or "5432").strip() or "5432"
            user = (os.environ.get("PG_USER") or "sanal").strip() or "sanal"
            password = (os.environ.get("PG_PASSWORD") or "").strip()
            db = (os.environ.get("PG_DB") or "sanal_mulakatim").strip() or "sanal_mulakatim"
            if password:
                # lightweight escaping
                from urllib.parse import quote

                pw = quote(password, safe="")
                url = f"postgresql://{user}:{pw}@{host}:{port}/{db}"
            else:
                url = f"postgresql://{user}@{host}:{port}/{db}"
        if not url:
            raise SystemExit("Postgres için DATABASE_URL veya PG_* env gerekli")
        mig_dir = Path(args.dir or "backend/migrations/postgres")
        if not mig_dir.exists():
            raise SystemExit(f"Migration dir not found: {mig_dir}")

        conn = _pg_connect(url)
        try:
            _pg_advisory_lock(conn)
            try:
                _pg_ensure_schema_migrations(conn)
                done = _pg_applied_set(conn)

                files = sorted([p for p in mig_dir.glob("*.sql") if p.is_file()])
                if not files:
                    print("No migrations found.")
                    return 0

                applied = 0
                for f in files:
                    mig_id = f.name.split(".sql")[0]
                    if mig_id in done:
                        continue
                    sql = f.read_text(encoding="utf-8")
                    print(f"Applying {mig_id} ...")
                    _pg_apply_one(conn, mig_id, sql)
                    applied += 1

                print(f"Done. Applied {applied} migrations.")
                return 0
            finally:
                try:
                    _pg_advisory_unlock(conn)
                except Exception:
                    pass
        finally:
            conn.close()

    # default: sqlite
    mig_dir = Path(args.dir or "backend/migrations/sql")
    if not mig_dir.exists():
        raise SystemExit(f"Migration dir not found: {mig_dir}")

    db_path = Path(args.db)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = _sqlite_connect(str(db_path))
    try:
        _sqlite_ensure_schema_migrations(conn)
        done = _sqlite_applied_set(conn)

        files = sorted([p for p in mig_dir.glob("*.sql") if p.is_file()])
        if not files:
            print("No migrations found.")
            return 0

        applied = 0
        for f in files:
            mig_id = f.name.split(".sql")[0]
            if mig_id in done:
                continue
            sql = f.read_text(encoding="utf-8")
            print(f"Applying {mig_id} ...")
            _sqlite_apply_one(conn, mig_id, sql)
            applied += 1

        print(f"Done. Applied {applied} migrations.")
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
