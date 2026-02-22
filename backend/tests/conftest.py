import importlib
import os
import sys

# Ensure backend/ is importable even if pytest rootdir is one level above.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def app_module(tmp_path, monkeypatch):
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

    import main  # noqa: F401
    importlib.reload(main)
    return main


@pytest.fixture()
def client(app_module):
    return TestClient(app_module.app)
