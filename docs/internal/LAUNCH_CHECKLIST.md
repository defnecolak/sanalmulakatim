# Public Launch Checklist (Sanal Mülakatım)

## 0) Mutlak gerekliler
- [ ] Domain DNS A kayıtları doğru (root + www)
- [ ] HTTPS/TLS çalışıyor (Caddy/Let’s Encrypt)
- [ ] `PUBLIC_BASE_URL=https://...` doğru
- [ ] `.env` secrets üretildi:
  - [ ] `SESSION_SECRET`, `CLIENT_ID_SALT`, `EMAIL_HASH_SALT`
  - [ ] `RECOVERY_TOKEN_SECRET`, `PRIVACY_DELETE_TOKEN_SECRET`
  - [ ] `ADMIN_STATUS_KEY` (uzun rastgele)
- [ ] Prod’da API docs kapalı (`ENABLE_API_DOCS=0`) ve edge’de de bloklu
- [ ] Admin panel internetten saklı:
  - [ ] IP allowlist
  - [ ] Basic Auth
  - [ ] (Varsa) Edge token / 2FA / TOTP

## 1) Ödeme
- [ ] iyzico / PayTR merchant onayı tamam
- [ ] Callback URL’ler doğru ve HTTPS
- [ ] “Ödedim ama Pro gelmedi” senaryosu test edildi:
  - [ ] Success retry/polling çalışıyor
  - [ ] Recovery akışı çalışıyor
- [ ] Idempotency (çift callback) test edildi

## 2) E-posta
- [ ] SMTP çalışıyor (prod domain mail)
- [ ] SPF/DKIM/DMARC kayıtları eklendi (spam riskini azaltır)
- [ ] Delete confirm e-postası teslim ediliyor
- [ ] Recovery e-postası teslim ediliyor

## 3) KVKK / metinler
- [ ] Gizlilik politikası “kısa ve net”
- [ ] İade politikası net
- [ ] İletişim e-posta doğru

## 4) Abuse / maliyet koruması
- [ ] Endpoint bazlı rate limit’ler ayarlı
- [ ] Weighted strikes + ban açık
- [ ] CAPTCHA (Turnstile) e-posta tetikleyen endpoint’lerde açık (önerilir)
- [ ] Lockdown (anomali) açık ve süre/eşikler mantıklı

## 5) Observability
- [ ] `/api/healthz` izleniyor (uptime)
- [ ] Sentry veya benzeri hata izleme açık (opsiyonel ama önerilir)
- [ ] Loglar merkezi (Loki/ELK) veya en azından rotate + backup var
- [ ] Alert webhook/email ayarlı (lockdown / ban spike / 5xx spike)

## 6) Backup / restore
- [ ] Günlük backup timer aktif (systemd)
- [ ] Haftalık integrity verify timer aktif
- [ ] Restore drill (en az ayda 1) planlandı ve denendi

### (Opsiyonel) SQLite → Postgres geçişi
- [ ] Postgres compose/migrate OK
- [ ] Eski SQLite verisi taşındı:
  - [ ] `backend/db_transfer_sqlite_to_postgres.py` çalıştı
  - [ ] Free deneme sayaçları doğru
  - [ ] Pro token / recovery / delete akışları doğru
  - [ ] Admin security events görünüyor (opsiyonel)

## 7) Yayın sonrası
- [ ] 1 saat: ban/429/WAF trendlerini izle
- [ ] 24 saat: maliyet ve performans raporu
- [ ] 7 gün: en çok support ticket çıkan noktaları düzelt
