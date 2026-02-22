def test_followups_autofilled_to_three(client, app_module, monkeypatch):
    def fake_chat_json(client, *, model, messages, max_tokens):
        return {
            "type": "davranışsal",
            "question": "Ekip içinde bir çatışmayı nasıl yönetirsin?",
            "followups": [],
        }

    monkeypatch.setattr(app_module, "_chat_json", fake_chat_json)
    monkeypatch.setattr(app_module, "_get_client", lambda: object())

    r = client.post(
        "/api/start",
        json={
            "role": "sekreter",
            "seniority": "Yeni Mezun",
            "language": "Türkçe",
            "n_questions": 1,
            "cv_text": "",
        },
        headers={"X-Client-ID": "cid_fu"},
    )
    assert r.status_code == 200
    q = r.json()["question"]
    assert isinstance(q["followups"], list)
    assert len(q["followups"]) == 3


def test_type_normalization_turkish(client, app_module, monkeypatch):
    def fake_chat_json(client, *, model, messages, max_tokens):
        return {
            "type": "behavioral",
            "question": "Zaman baskısı altında nasıl önceliklendirirsin?",
            "followups": ["Kriterlerin ne olur?", "Paydaşları nasıl bilgilendirirsin?", "Sonuç neydi?"],
        }

    monkeypatch.setattr(app_module, "_chat_json", fake_chat_json)
    monkeypatch.setattr(app_module, "_get_client", lambda: object())

    r = client.post(
        "/api/start",
        json={
            "role": "sekreter",
            "seniority": "Orta Seviye",
            "language": "Türkçe",
            "n_questions": 1,
            "cv_text": "",
        },
        headers={"X-Client-ID": "cid_type"},
    )
    assert r.status_code == 200
    q = r.json()["question"]
    assert q["type"] == "davranışsal"


def test_invalid_role_content_retries(client, app_module, monkeypatch):
    calls = {"n": 0}

    def fake_chat_json(client, *, model, messages, max_tokens):
        calls["n"] += 1
        if calls["n"] == 1:
            return {
                "type": "vaka",
                "question": "Hastanede SIEM alarmı geldiğinde ne yaparsın?",
                "followups": ["Loglara bakar mısın?", "Containment?", "Rapor?"],
            }
        return {
            "type": "vaka",
            "question": "Acil serviste dispne ile gelen bir hastada ilk yaklaşımını nasıl anlatırsın?",
            "followups": ["Önceliğin ne olur?", "Ekip iletişimini nasıl kurarsın?", "Sonucu nasıl takip edersin?"],
        }

    monkeypatch.setattr(app_module, "_chat_json", fake_chat_json)
    monkeypatch.setattr(app_module, "_get_client", lambda: object())

    r = client.post(
        "/api/start",
        json={
            "role": "doktor",
            "seniority": "Orta Seviye",
            "language": "Türkçe",
            "n_questions": 1,
            "cv_text": "Siber güvenlik CV...",
        },
        headers={"X-Client-ID": "cid_retry"},
    )
    assert r.status_code == 200
    q = r.json()["question"]
    assert "SIEM" not in q["question"].upper()
    assert calls["n"] >= 2
