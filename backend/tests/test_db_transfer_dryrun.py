import sqlite3
import subprocess
import sys
from pathlib import Path


def test_db_transfer_dry_run(tmp_path):
    # Create a tiny SQLite DB with a couple of tables.
    db = tmp_path / "usage.db"
    con = sqlite3.connect(str(db))
    try:
        con.execute(
            "CREATE TABLE usage_total(client_id TEXT, key TEXT, count INTEGER, PRIMARY KEY (client_id, key))"
        )
        con.execute(
            "INSERT INTO usage_total(client_id, key, count) VALUES ('c1', 'eval', 2), ('c2', 'eval', 1)"
        )
        con.execute(
            "CREATE TABLE ip_bans(ban_key TEXT PRIMARY KEY, reason TEXT, created_at INTEGER, expires_at INTEGER)"
        )
        con.execute(
            "INSERT INTO ip_bans(ban_key, reason, created_at, expires_at) VALUES ('abc', 'test', 1, 2)"
        )
        con.commit()
    finally:
        con.close()

    script = Path(__file__).resolve().parents[1] / "db_transfer_sqlite_to_postgres.py"

    out = subprocess.check_output(
        [sys.executable, str(script), "--sqlite", str(db), "--dry-run"],
        text=True,
    )

    assert "DRY RUN" in out
    assert "usage_total" in out
    assert "ip_bans" in out
