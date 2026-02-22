class _Resp:
    pass


def test_email_token_endpoint_sends_email(client, app_module, monkeypatch):
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

    monkeypatch.setattr(app_module.smtplib, "SMTP", DummySMTP)

    # Add token to DB so endpoint accepts it
    app_module.usage_db.add_pro_token(token="pro_testtoken", client_id="cid_z", provider="manual", provider_ref="ref1")

    r = client.post(
        "/api/billing/email_token",
        json={"email": "user@example.com", "token": "pro_testtoken"},
        headers={"X-Client-ID": "cid_z"},
    )
    assert r.status_code == 200
    assert r.json()["ok"] is True
    assert len(sent) == 1
    assert "user@example.com" in (sent[0]["To"] or "")
