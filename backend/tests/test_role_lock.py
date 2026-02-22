def test_role_lock_prompt_prevents_cv_hijack(client, app_module, monkeypatch):
    captured = {}

    def fake_chat_json(client, *, model, messages, max_tokens):
        # messages[1] is user prompt in our code
        captured["user"] = messages[1]["content"]
        return {
            "type": "davranışsal",
            "question": "Acil serviste stres altında iletişimi nasıl yönetirsin?",
            "followups": ["Örnek ver", "Ekip içi çatışma oldu mu?", "Sonuç neydi?"],
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
            "cv_text": "Siber güvenlik alanında SOC analisti olarak 3 yıl çalıştım...",
        },
        headers={"X-Client-ID": "cid_rl"},
    )
    assert r.status_code == 200
    assert "Hedef Rol: doktor" in captured["user"]
    # the anti-hijack rule should be present
    assert "Hedef rol SAĞLIK/HEKİMLİK" in captured["user"]
    assert "transfer edilebilir" in captured["user"]
