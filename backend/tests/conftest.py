import gc
import importlib
import os
import sys

# Ensure backend/ is importable even if pytest rootdir is one level above.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import pytest
from fastapi.testclient import TestClient


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


@pytest.fixture()
def app_module(tmp_path, monkeypatch):
    _close_main_module()

    # Minimal env to boot the app in a test-safe way
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("OPENAI_MODEL", "gpt-4o-mini")

    # Use a temp sqlite DB for isolation
    monkeypatch.setenv("USAGE_DB_PATH", str(tmp_path / "usage.db"))

    # Disable sentry in tests
    monkeypatch.delenv("SENTRY_DSN", raising=False)

    # Configure iyzico (no real network calls; tests will mock requests.post)
    monkeypatch.setenv("PAYMENT_PROVIDER", "iyzico")
    monkeypatch.setenv("IYZICO_API_KEY", "sandbox-test")
    monkeypatch.setenv("IYZICO_SECRET_KEY", "sandbox-secret")
    monkeypatch.setenv("IYZICO_BASE_URL", "https://sandbox-api.iyzipay.com")

    # iyzico requires https callback base (docs). Use a dummy https domain.
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://example.com")

    # The repo ships with a local-dev .env. Force test-safe host/origin settings so
    # TrustedHost / Origin guard don't accidentally reject TestClient requests.
    monkeypatch.setenv("ALLOWED_HOSTS", "testserver,localhost,127.0.0.1")
    monkeypatch.setenv("ALLOWED_ORIGINS", "https://example.com,http://testserver")

    main = importlib.import_module("main")
    try:
        yield main
    finally:
        _close_main_module()


@pytest.fixture()
def client(app_module):
    with TestClient(app_module.app) as c:
        yield c
