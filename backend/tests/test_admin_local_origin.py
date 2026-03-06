import gc
import importlib
import sys

from fastapi.testclient import TestClient


def _fresh_main():
    mod = sys.modules.get("main")
    if mod is not None:
        for attr in ("usage_db", "ban_db", "security_events"):
            obj = getattr(mod, attr, None)
            close_fn = getattr(obj, "close", None)
            if callable(close_fn):
                try:
                    close_fn()
                except Exception:
                    pass
        sys.modules.pop("main", None)
    gc.collect()
    return importlib.import_module("main")


def _close_main_module() -> None:
    mod = sys.modules.get("main")
    if mod is not None:
        for attr in ("usage_db", "ban_db", "security_events"):
            obj = getattr(mod, attr, None)
            close_fn = getattr(obj, "close", None)
            if callable(close_fn):
                try:
                    close_fn()
                except Exception:
                    pass
        sys.modules.pop("main", None)
    gc.collect()


def test_admin_security_summary_allows_local_admin_origin(monkeypatch, tmp_path):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("OPENAI_MODEL", "gpt-4o-mini")
    monkeypatch.setenv("USAGE_DB_PATH", str(tmp_path / "usage.db"))
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://example.com")
    monkeypatch.setenv("ALLOWED_ORIGINS", "https://example.com")
    monkeypatch.setenv("ADMIN_STATUS_KEY", "adminkey")
    monkeypatch.setenv("ADMIN_EDGE_TOKEN", "")
    monkeypatch.delenv("SENTRY_DSN", raising=False)

    main = _fresh_main()
    try:
        with TestClient(main.app, base_url="http://127.0.0.1:8081") as client:
            r = client.get(
                "/api/admin/security/summary?minutes=60",
                headers={
                    "X-Admin-Key": "adminkey",
                    "Origin": "http://127.0.0.1:8081",
                },
            )
            assert r.status_code == 200
            assert "minutes" in r.json()
    finally:
        _close_main_module()


def test_admin_lockdown_post_allows_local_admin_origin(monkeypatch, tmp_path):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("OPENAI_MODEL", "gpt-4o-mini")
    monkeypatch.setenv("USAGE_DB_PATH", str(tmp_path / "usage.db"))
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://example.com")
    monkeypatch.setenv("ALLOWED_ORIGINS", "https://example.com")
    monkeypatch.setenv("ADMIN_STATUS_KEY", "adminkey")
    monkeypatch.setenv("ADMIN_EDGE_TOKEN", "")
    monkeypatch.delenv("SENTRY_DSN", raising=False)

    main = _fresh_main()
    try:
        with TestClient(main.app, base_url="http://127.0.0.1:8081") as client:
            r = client.post(
                "/api/admin/security/lockdown",
                json={"action": "activate", "ttl_sec": 30},
                headers={
                    "X-Admin-Key": "adminkey",
                    "Origin": "http://127.0.0.1:8081",
                    "Sec-Fetch-Site": "same-origin",
                },
            )
            assert r.status_code == 200
            assert r.json()["active"] is True
    finally:
        _close_main_module()
