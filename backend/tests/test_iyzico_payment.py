import hashlib
import hmac
import json


class _Resp:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


def _norm(name, value):
    s = "" if value is None else str(value).strip()
    if not s:
        return ""
    if name not in {"price", "paidPrice"}:
        return s
    if "." in s:
        s = s.rstrip("0").rstrip(".")
    return s or "0"


def _sign(secret, payload, fields):
    plain = ":".join(_norm(field, payload.get(field)) for field in fields)
    return hmac.new(secret.encode("utf-8"), plain.encode("utf-8"), hashlib.sha256).hexdigest()


def _decode_body(data):
    if isinstance(data, (bytes, bytearray)):
        return json.loads(data.decode("utf-8"))
    if isinstance(data, str):
        return json.loads(data)
    raise AssertionError(f"Unexpected request body type: {type(data).__name__}")


def test_iyzico_create_checkout_returns_url(client, app_module, monkeypatch):
    calls = []
    secret = app_module._env_str("IYZICO_SECRET_KEY")

    def fake_post(url, headers=None, data=None, timeout=None):
        calls.append((url, headers, data))
        payload = _decode_body(data)
        token = "tok_1"
        resp = {
            "status": "success",
            "conversationId": payload["conversationId"],
            "paymentPageUrl": "https://sandbox-cpp.iyzipay.com/checkout?token=tok_1",
            "token": token,
        }
        resp["signature"] = _sign(secret, resp, ["conversationId", "token"])
        return _Resp(200, resp)

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
    secret = app_module._env_str("IYZICO_SECRET_KEY")

    def fake_post(url, headers=None, data=None, timeout=None):
        payload = _decode_body(data)
        if url.endswith("/payment/iyzipos/checkoutform/initialize/auth/ecom"):
            resp = {
                "status": "success",
                "conversationId": payload["conversationId"],
                "paymentPageUrl": "https://sandbox-cpp.iyzipay.com/checkout?token=tok_2",
                "token": "tok_2",
            }
            resp["signature"] = _sign(secret, resp, ["conversationId", "token"])
            return _Resp(200, resp)
        if url.endswith("/payment/iyzipos/checkoutform/auth/ecom/detail"):
            resp = {
                "status": "success",
                "paymentStatus": "SUCCESS",
                "paymentId": "pay_iyzi_1",
                "currency": "TRY",
                "basketId": payload["conversationId"],
                "conversationId": payload["conversationId"],
                "paidPrice": 199.0,
                "price": 199.0,
                "token": payload["token"],
                "fraudStatus": 1,
            }
            resp["signature"] = _sign(secret, resp, ["paymentStatus", "paymentId", "currency", "basketId", "conversationId", "paidPrice", "price", "token"])
            return _Resp(200, resp)
        raise AssertionError("Unexpected iyzico url: " + url)

    monkeypatch.setattr(app_module.requests, "post", fake_post)

    r = client.post("/api/billing/create_checkout", json={"email": "user@example.com"}, headers={"X-Client-ID": "cid_x"})
    assert r.status_code == 200
    order_id = r.json()["order_id"]

    r2 = client.post(f"/api/billing/iyzico/callback?order_id={order_id}", data={"token": "tok_2"})
    assert r2.status_code == 200
    assert "/success?provider=iyzico" in r2.text

    r3 = client.get(f"/api/billing/redeem?provider=iyzico&ref={order_id}", headers={"X-Client-ID": "cid_x"})
    assert r3.status_code == 200
    token = r3.json()["token"]
    assert token.startswith("pro_")



def test_iyzico_auto_email_on_success(client, app_module, monkeypatch):
    sent = []
    secret = app_module._env_str("IYZICO_SECRET_KEY")

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

    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SMTP_PORT", "587")
    monkeypatch.setenv("SMTP_FROM", "support@example.com")
    monkeypatch.setenv("SMTP_FROM_NAME", "Sanal Mülakatım")
    monkeypatch.setenv("SMTP_USE_TLS", "0")
    monkeypatch.setenv("SMTP_USE_SSL", "0")
    monkeypatch.setenv("AUTO_EMAIL_TOKEN_ON_PAYMENT", "1")

    monkeypatch.setattr(app_module.smtplib, "SMTP", DummySMTP)

    def fake_post(url, headers=None, data=None, timeout=None):
        payload = _decode_body(data)
        if url.endswith("/payment/iyzipos/checkoutform/initialize/auth/ecom"):
            resp = {
                "status": "success",
                "conversationId": payload["conversationId"],
                "paymentPageUrl": "https://sandbox-cpp.iyzipay.com/checkout?token=tok_3",
                "token": "tok_3",
            }
            resp["signature"] = _sign(secret, resp, ["conversationId", "token"])
            return _Resp(200, resp)
        if url.endswith("/payment/iyzipos/checkoutform/auth/ecom/detail"):
            resp = {
                "status": "success",
                "paymentStatus": "SUCCESS",
                "paymentId": "pay_iyzi_2",
                "currency": "TRY",
                "basketId": payload["conversationId"],
                "conversationId": payload["conversationId"],
                "paidPrice": 199.0,
                "price": 199.0,
                "token": payload["token"],
                "fraudStatus": 1,
            }
            resp["signature"] = _sign(secret, resp, ["paymentStatus", "paymentId", "currency", "basketId", "conversationId", "paidPrice", "price", "token"])
            return _Resp(200, resp)
        raise AssertionError("Unexpected iyzico url: " + url)

    monkeypatch.setattr(app_module.requests, "post", fake_post)

    r = client.post("/api/billing/create_checkout", json={"email": "user@example.com"}, headers={"X-Client-ID": "cid_y"})
    order_id = r.json()["order_id"]

    r2 = client.post(f"/api/billing/iyzico/callback?order_id={order_id}", data={"token": "tok_3"})
    assert r2.status_code == 200
    assert "emailed=1" in r2.text

    assert len(sent) == 1
    msg = sent[0]
    assert "user@example.com" in (msg["To"] or "")
    assert "Pro Anahtarın" in (msg["Subject"] or "")



def test_iyzico_callback_waits_when_fraud_review_pending(client, app_module, monkeypatch):
    secret = app_module._env_str("IYZICO_SECRET_KEY")

    def fake_post(url, headers=None, data=None, timeout=None):
        payload = _decode_body(data)
        if url.endswith("/payment/iyzipos/checkoutform/initialize/auth/ecom"):
            resp = {
                "status": "success",
                "conversationId": payload["conversationId"],
                "paymentPageUrl": "https://sandbox-cpp.iyzipay.com/checkout?token=tok_review",
                "token": "tok_review",
            }
            resp["signature"] = _sign(secret, resp, ["conversationId", "token"])
            return _Resp(200, resp)
        if url.endswith("/payment/iyzipos/checkoutform/auth/ecom/detail"):
            resp = {
                "status": "success",
                "paymentStatus": "SUCCESS",
                "paymentId": "pay_iyzi_review",
                "currency": "TRY",
                "basketId": payload["conversationId"],
                "conversationId": payload["conversationId"],
                "paidPrice": 199.0,
                "price": 199.0,
                "token": payload["token"],
                "fraudStatus": 0,
            }
            resp["signature"] = _sign(secret, resp, ["paymentStatus", "paymentId", "currency", "basketId", "conversationId", "paidPrice", "price", "token"])
            return _Resp(200, resp)
        raise AssertionError("Unexpected iyzico url: " + url)

    monkeypatch.setattr(app_module.requests, "post", fake_post)

    r = client.post("/api/billing/create_checkout", json={"email": "user@example.com"}, headers={"X-Client-ID": "cid_review"})
    order_id = r.json()["order_id"]

    r2 = client.post(f"/api/billing/iyzico/callback?order_id={order_id}", data={"token": "tok_review"})
    assert r2.status_code == 200
    assert "/cancel" in r2.text

    r3 = client.get(f"/api/billing/redeem?provider=iyzico&ref={order_id}", headers={"X-Client-ID": "cid_review"})
    assert r3.status_code == 404
