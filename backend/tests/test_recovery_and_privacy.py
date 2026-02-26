import re


def test_magic_link_recovery_flow(client, app_module, monkeypatch):
    sent = []

    class DummySMTP:
        def __init__(self, host, port, timeout=None):
            self.host = host
            self.port = port

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
    monkeypatch.setenv("SMTP_USE_TLS", "0")
    monkeypatch.setenv("SMTP_USE_SSL", "0")
    monkeypatch.setenv("RECOVERY_TOKEN_SECRET", "testsecret")
    monkeypatch.setenv("PUBLIC_BASE_URL", "http://localhost:5555")
    monkeypatch.setattr(app_module.smtplib, "SMTP", DummySMTP)

    # Add token & link email -> token
    app_module.usage_db.add_pro_token(token="pro_testtoken", client_id="cid_a", provider="manual", provider_ref="ref1")
    app_module.usage_db.link_email_to_token("user@example.com", "pro_testtoken")

    r = client.post(
        "/api/pro/recovery/request",
        json={"email": "user@example.com"},
        headers={"X-Client-ID": "cid_a"},
    )
    assert r.status_code == 200
    assert r.json()["ok"] is True
    assert len(sent) == 1

    body = sent[0].get_content()
    m = re.search(r"token=([a-zA-Z0-9_\-]+)", body)
    assert m, body
    token = m.group(1)

    c = client.post(
        "/api/pro/recovery/consume",
        json={"token": token},
        headers={"X-Client-ID": "cid_a"},
    )
    assert c.status_code == 200
    assert "pro_testtoken" in c.json().get("tokens", [])

    # One-time token
    c2 = client.post(
        "/api/pro/recovery/consume",
        json={"token": token},
        headers={"X-Client-ID": "cid_a"},
    )
    assert c2.status_code == 400


def test_privacy_delete_anonymizes_email_data(client, app_module, monkeypatch):
    sent = []

    class DummySMTP:
        def __init__(self, host, port, timeout=None):
            self.host = host
            self.port = port

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
    monkeypatch.setenv("SMTP_USE_TLS", "0")
    monkeypatch.setenv("SMTP_USE_SSL", "0")
    monkeypatch.setenv("PUBLIC_BASE_URL", "http://localhost:5555")
    monkeypatch.setattr(app_module.smtplib, "SMTP", DummySMTP)

    # Seed
    app_module.usage_db.add_pro_token(token="pro_tok2", client_id="cid_b", provider="manual", provider_ref="ref2")
    app_module.usage_db.link_email_to_token("delme@example.com", "pro_tok2")
    app_module.usage_db.create_payment_order(order_id="ord1", provider="iyzico", client_id="cid_b", email="delme@example.com")

    r = client.post(
        "/api/privacy/delete/request",
        json={"email": "delme@example.com"},
        headers={"X-Client-ID": "cid_b"},
    )
    assert r.status_code == 200
    assert r.json()["ok"] is True

    assert len(sent) == 1
    body = sent[0].get_content()
    m = re.search(r"token=([a-zA-Z0-9_\-]+)", body)
    assert m, body
    token = m.group(1)

    c = client.post(
        "/api/privacy/delete/confirm",
        json={"token": token},
        headers={"X-Client-ID": "cid_b"},
    )
    assert c.status_code == 200
    assert c.json()["ok"] is True

    # Link removed
    assert app_module.usage_db.get_tokens_for_email("delme@example.com") == []

    # Payment order anonymized
    o = app_module.usage_db.get_payment_order("ord1")
    assert o is not None
    assert o.get("email") in (None, "")
    assert o.get("email_hash") in (None, "")