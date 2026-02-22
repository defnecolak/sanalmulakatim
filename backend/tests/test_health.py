def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    j = r.json()
    assert j["ok"] is True
    assert j["payment_provider"] == "iyzico"
    assert j["iyzico_configured"] is True
