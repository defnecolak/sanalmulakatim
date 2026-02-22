import types


class _Resp:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


def test_iyzico_create_checkout_returns_url(client, app_module, monkeypatch):
    calls = []

    def fake_post(url, headers=None, data=None, timeout=None):
        calls.append((url, headers, data))
        # initialize endpoint should return paymentPageUrl (hosted page)
        return _Resp(200, {"status": "success", "paymentPageUrl": "https://sandbox-cpp.iyzipay.com/checkout?token=tok_1", "token": "tok_1"})

    monkeypatch.setattr(app_module.requests, "post", fake_post)

    r = client.post(
        "/api/billing/create_checkout",
        json={"email": "user@example.com"},
        headers={"X-Client-ID": "cid_test"},
    )
    assert r.status_code == 200
    j = r.json()
    assert j["provider"] == "iyzico"
    assert j["url"].startswith("https://")
    assert "order_id" in j
    assert len(calls) == 1


def test_iyzico_callback_mints_token_and_redeem_works(client, app_module, monkeypatch):
    # Mock iyzico: first call = initialize, second call = retrieve
    def fake_post(url, headers=None, data=None, timeout=None):
        if url.endswith("/payment/iyzipos/checkoutform/initialize/auth/ecom"):
            return _Resp(200, {"status": "success", "paymentPageUrl": "https://sandbox-cpp.iyzipay.com/checkout?token=tok_2", "token": "tok_2"})
        if url.endswith("/payment/iyzipos/checkoutform/auth/ecom/detail"):
            return _Resp(200, {"status": "success", "paymentStatus": "SUCCESS"})
        raise AssertionError("Unexpected iyzico url: " + url)

    monkeypatch.setattr(app_module.requests, "post", fake_post)

    # Create an order
    r = client.post("/api/billing/create_checkout", json={"email": "user@example.com"}, headers={"X-Client-ID": "cid_x"})
    assert r.status_code == 200
    order_id = r.json()["order_id"]

    # Callback (iyzico posts token as form-data)
    r2 = client.post(f"/api/billing/iyzico/callback?order_id={order_id}", data={"token": "tok_2"})
    assert r2.status_code == 200
    assert "/success?provider=iyzico" in r2.text

    # Redeem token
    r3 = client.get(f"/api/billing/redeem?provider=iyzico&ref={order_id}", headers={"X-Client-ID": "cid_x"})
    assert r3.status_code == 200
    token = r3.json()["token"]
    assert token.startswith("pro_")


def test_iyzico_auto_email_on_success(client, app_module, monkeypatch):
    sent = []

    class DummySMTP:
        def __init__(self, host, port, timeout=None):
            self.host = host
            self.port = port
            self.timeout = timeout

        def ehlo(self):
            return None

        def starttls(self):
            return None

        def login(self, user, pwd):
            return None

        def send_message(self, msg):
            sent.append(msg)

        def quit(self):
            return None

    # Enable SMTP + auto email
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SMTP_PORT", "587")
    monkeypatch.setenv("SMTP_FROM", "support@example.com")
    monkeypatch.setenv("SMTP_FROM_NAME", "Sanal Mülakatım")
    monkeypatch.setenv("SMTP_USE_TLS", "0")
    monkeypatch.setenv("SMTP_USE_SSL", "0")
    monkeypatch.setenv("AUTO_EMAIL_TOKEN_ON_PAYMENT", "1")

    monkeypatch.setattr(app_module.smtplib, "SMTP", DummySMTP)

    # Mock iyzico: initialize + retrieve success
    def fake_post(url, headers=None, data=None, timeout=None):
        if url.endswith("/payment/iyzipos/checkoutform/initialize/auth/ecom"):
            return _Resp(200, {"status": "success", "paymentPageUrl": "https://sandbox-cpp.iyzipay.com/checkout?token=tok_3", "token": "tok_3"})
        if url.endswith("/payment/iyzipos/checkoutform/auth/ecom/detail"):
            return _Resp(200, {"status": "success", "paymentStatus": "SUCCESS"})
        raise AssertionError("Unexpected iyzico url: " + url)

    monkeypatch.setattr(app_module.requests, "post", fake_post)

    r = client.post("/api/billing/create_checkout", json={"email": "user@example.com"}, headers={"X-Client-ID": "cid_y"})
    order_id = r.json()["order_id"]

    r2 = client.post(f"/api/billing/iyzico/callback?order_id={order_id}", data={"token": "tok_3"})
    assert r2.status_code == 200
    assert "emailed=1" in r2.text  # server appended this if mail was sent

    assert len(sent) == 1
    msg = sent[0]
    assert "user@example.com" in (msg["To"] or "")
    assert "Pro Anahtarın" in (msg["Subject"] or "")
