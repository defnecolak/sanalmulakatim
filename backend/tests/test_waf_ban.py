import importlib
import os
import sys
from pathlib import Path

from fastapi.testclient import TestClient


def _fresh_client(env: dict) -> TestClient:
    # Apply env overrides
    for k, v in env.items():
        os.environ[k] = str(v)

    # Ensure a fresh import so module-level config is re-evaluated
    if "main" in sys.modules:
        del sys.modules["main"]
    m = importlib.import_module("main")
    return TestClient(m.app)


def test_waf_blocks_known_bad_paths(tmp_path: Path):
    db_path = tmp_path / "test_usage.db"
    client = _fresh_client({
        "DB_PATH": str(db_path),
        "SESSION_SECRET": "test-secret",
        "CLIENT_ID_SALT": "test-salt",
        "ORIGIN_GUARD_ENABLED": "0",
        "WAF_ENABLED": "1",
        "WAF_BLOCK": "1",
        "BAN_ENABLED": "0",
    })

    r = client.get("/wp-admin")
    assert r.status_code == 403
    body = r.json()
    assert "request_id" in body


def test_waf_blocks_script_in_query(tmp_path: Path):
    db_path = tmp_path / "test_usage.db"
    client = _fresh_client({
        "DB_PATH": str(db_path),
        "SESSION_SECRET": "test-secret",
        "CLIENT_ID_SALT": "test-salt",
        "ORIGIN_GUARD_ENABLED": "0",
        "WAF_ENABLED": "1",
        "WAF_BLOCK": "1",
        "BAN_ENABLED": "0",
    })

    r = client.get("/api/health?x=%3Cscript%3Ealert(1)%3C/script%3E")
    assert r.status_code == 403


def test_ban_kicks_in_after_repeated_waf_hits(tmp_path: Path):
    db_path = tmp_path / "test_usage.db"
    client = _fresh_client({
        "DB_PATH": str(db_path),
        "SESSION_SECRET": "test-secret",
        "CLIENT_ID_SALT": "test-salt",
        "ORIGIN_GUARD_ENABLED": "0",
        "WAF_ENABLED": "1",
        "WAF_BLOCK": "1",
        "BAN_ENABLED": "1",
        "BAN_WINDOW_SEC": "60",
        "BAN_THRESHOLD": "3",
        "BAN_TTL_SEC": "600",
    })

    # 3 WAF triggers => ban on the 3rd (next clean request is blocked by ban)
    for _ in range(3):
        r = client.get("/api/health?x=%3Cscript%3E")
        assert r.status_code == 403

    r2 = client.get("/api/health")
    assert r2.status_code == 403
    assert "Geçici" in r2.json().get("detail", "")
