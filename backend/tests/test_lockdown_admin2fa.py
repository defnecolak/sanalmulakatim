import time


def test_lockdown_blocks_expensive_endpoint(app_module, client):
    # Configure lockdown to trigger on a single waf_trigger event
    app_module.LOCKDOWN_ENABLED = True
    app_module.LOCKDOWN_WINDOW_SEC = 3600
    app_module.LOCKDOWN_THRESHOLD_EVENTS = 1
    app_module.LOCKDOWN_THRESHOLD_SOURCES = 1
    app_module.LOCKDOWN_TTL_SEC = 300
    app_module.LOCKDOWN_CHECK_EVERY_SEC = 0
    app_module.LOCKDOWN_EVENT_TYPES = ["waf_trigger"]
    app_module.LOCKDOWN_BLOCK_PREFIXES = ["/api/evaluate"]

    # Reset manager state
    app_module.lockdown_mgr.active_until = 0
    app_module.lockdown_mgr.forced_until = 0
    app_module.lockdown_mgr.last_check = 0

    # Record a security event to trip the detector
    app_module.security_events.log(
        "waf_trigger",
        ban_key="test",
        client_id="c",
        method="GET",
        path="/x",
        status=403,
        ua="pytest",
        details={"ts": int(time.time())},
    )

    r = client.post("/api/evaluate", json={"session_id": "dummy", "answer": "x"})
    assert r.status_code == 503
    j = r.json()
    assert "kısıtlandı" in (j.get("detail") or "")


def test_admin_requires_2fa_when_enabled(app_module, client):
    # Enable admin + 2FA requirement
    app_module.ADMIN_STATUS_KEY = "adminkey"
    app_module.ADMIN_2FA_KEY = "twofa"
    app_module.ADMIN_EDGE_TOKEN = ""  # no edge header requirement in tests

    r = client.get(
        "/api/admin/security/summary?minutes=60",
        headers={"X-Admin-Key": "adminkey"},
    )
    assert r.status_code == 403

    r2 = client.get(
        "/api/admin/security/summary?minutes=60",
        headers={"X-Admin-Key": "adminkey", "X-Admin-2FA": "twofa"},
    )
    assert r2.status_code == 200
