# Production Runbook

## Hızlı komutlar
### Status
```bash
docker compose --env-file deploy/.env -f deploy/docker-compose.prod.yml ps
docker compose --env-file deploy/.env -f deploy/docker-compose.prod.yml logs -f --tail=200
curl -fsS https://DOMAIN/api/healthz
```

### Loglar
- Caddy access log: `deploy/logs/access.log`
- App log: `backend/data/app.log`

### Restart
```bash
docker compose --env-file deploy/.env -f deploy/docker-compose.prod.yml restart app
docker compose --env-file deploy/.env -f deploy/docker-compose.prod.yml restart caddy
```

## Lockdown yönetimi
- Lockdown otomatik tetiklenebilir (anomali/spike).
- Admin panel üzerinden veya admin API ile aç/kapat.

## Ban / WAF
- Bot taraması artarsa önce:
  - rate limit sıkılaştır
  - CAPTCHA zorunlulaştır (özellikle mail tetikleyen endpoint’ler)
  - ban TTL’i artır
- False-positive olursa:
  - BAN_THRESHOLD’ı artır
  - WAF pattern setini daralt

## “Ödedim ama Pro gelmedi”
1) Loglarda callback geldi mi?
2) `redeem` retry/polling çalışıyor mu?
3) Recovery akışı kullanıcıya gönderildi mi?
4) Gerekirse admin endpoint ile token yeniden üret (idempotent)

## “E-posta gelmedi”
- SMTP logları
- SPF/DKIM/DMARC kontrol
- Spam klasörü
- Rate limit / CAPTCHA çok agresif mi?

## Deploy
- Blue/Green önerilir (deploy/bluegreen).
- SQLite ile gerçek zero-downtime zordur; Postgres geçişi planla.

## SQLite → Postgres geçişi (tek sefer)

- Taşıma + sayım doğrulaması + arşiv + read-only:
  - `deploy/runbook/transfer_sqlite_to_postgres.sh`
- Taşıma sonrası kritik akış smoke:
  - `deploy/runbook/smoke_critical_flows.sh`
- Tek komut (transfer + restart + smoke):
  - `deploy/runbook/transfer_verify_smoke.sh`

> Not: Smoke test e-posta göndermez; test için küçük DB kayıtları ekler ve temizler.
