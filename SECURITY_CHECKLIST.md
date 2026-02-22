# Sanal Mülakatım – Launch Security Checklist

Bu proje zaten “defense-in-depth” (katmanlı savunma) yaklaşımıyla sertleştirilmiş durumda (WAF + akıllı rate-limit + strike/ban + admin panel kilidi + delete token doğrulama).
Yine de **prod** ortamında “hack’lenmesi zor” yapmak; kod kadar **operasyon** (deploy, erişim, izleme, güncelleme) işidir.

## 1) Sunucu / ağ

- **Firewall (UFW/iptables):** Sadece 80/443 (ve gerekiyorsa 22/SSH) açık kalsın.
- **SSH sertleştirme:** Parola kapalı, sadece SSH key; mümkünse 22 yerine farklı port; rate-limit.
- **Otomatik güncelleme:** OS security updates açık (en azından security repos).
- **DNS / TLS:** HTTPS zorunlu, HSTS açık (Caddy + backend zaten).
- **Reverse proxy arkasında çalıştır:** Backend doğrudan internete açılmasın.

## 2) Docker / container

- **Non-root container:** Bu zip’te Dockerfile non-root kullanıcı ile çalışacak şekilde güncellendi.
- **read-only filesystem:** docker-compose.prod.yml içinde `read_only: true` + `tmpfs: /tmp`.
- **no-new-privileges + cap_drop:** Compose içinde etkin.
- **Volume izinleri:** Sadece `/app/backend/data` gibi gerekli path’ler writeable.

## 3) Uygulama katmanı (API)

- **Endpoint bazlı rate-limit:** evaluate / billing / pro gibi endpoint’ler farklı limitlerde.
- **Strike-weight ban:** WAF tetiklenmesi, 429, big body vb. farklı ağırlıklarla ban skoruna eklenir.
- **Body size guard:** Büyük payload’lar 413 ile erken kesilir (Caddy + backend).
- **Origin/Host guard:** CSRF benzeri cross-site denemeleri düşürür.
- **CSP & güvenlik başlıkları:** CSP (script-src self + Turnstile), HSTS, nosniff, referrer-policy vb. aktif. Ses kaydı için `media-src blob:` izinli.
- **Admin panel:** Hem backend `x-admin-key` kontrolü, hem Caddy BasicAuth + IP allowlist.

## 4) İzleme / logging

- **Security panel:** `/admin/security` panelinden son güvenlik eventleri + ban durumu izlenebilir.
- **Log rotasyonu:** Docker log driver veya Caddy logları için rotasyon ayarı düşün.
- **Alert:** “ban spike”, “429 spike”, “billing hata spike” gibi olaylarda e-posta/Slack alarm önerilir.

## 5) Güncelleme & supply-chain

- **Dependency taraması:** `pip-audit` / `bandit` / `ruff` ile düzenli tarama.
- **Pin’leme:** requirements.txt (mümkünse) versiyon pin’li olsun.
- **Secrets:** `.env` git’e asla girmez; prod secrets bir secret manager’da tutulur.

## 6) Backups & incident plan

- **SQLite backup:** `/app/backend/data/app.db` düzenli snapshot + offsite backup.
- **Playbook:** “Ödeme callback bozuldu”, “WAF false positive”, “IP ban dalgası” gibi senaryolar için kısa checklist.

> Not: “%100 hacklenmez” diye bir şey yok. Ama bu checklist’i uygularsan,
> saldırganların maliyeti artar, hataların etkisi azalır, müdahale hızın artar.
