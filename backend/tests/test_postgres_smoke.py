import os
import subprocess

import pytest


@pytest.mark.skipif(
    not (os.environ.get("DATABASE_URL") or os.environ.get("DB_ENGINE") == "postgres"),
    reason="Postgres smoke test requires DATABASE_URL or DB_ENGINE=postgres",
)
def test_postgres_migrations_and_basic_ops():
    # Run migrations (idempotent)
    subprocess.check_call(
        [
            "python",
            "backend/db_migrate.py",
            "--engine",
            "postgres",
            "--dir",
            "backend/migrations/postgres",
        ]
    )

    # Import after migrations
    from backend.main import usage_db
    from backend.security_controls import BanDB, SecurityEventDB

    # Basic counters
    c = "test-client"
    assert usage_db.inc_total(c, "eval", 1) >= 1
    assert usage_db.inc_total(c, "eval", 1) >= 2

    # Ban DB
    ban_db = BanDB("/tmp/ignored.db")
    key = "abc123"
    ban_db.ban(key, ttl_sec=5, reason="test")
    assert ban_db.is_banned(key) is True

    # Security events
    sec = SecurityEventDB("/tmp/ignored.db", retention_days=1)
    sec.log("test_event", ban_key=key, path="/api/test", status=200, details={"ok": True})
    s = sec.summary(minutes=60)
    assert "by_type" in s
