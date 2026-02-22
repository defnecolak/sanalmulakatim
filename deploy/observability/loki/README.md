# Observability (Loki + Promtail + Grafana)

Bu stack, dosya loglarını Loki’ye gönderir ve Grafana’dan aramayı sağlar.

## Start
```bash
cd deploy/observability/loki
docker compose -f docker-compose.loki.yml up -d
```

## Erişim (güvenli)
Grafana varsayılan olarak **localhost**’a bind edilir:
- http://127.0.0.1:3000

Sunucudan erişmek için SSH tunnel önerilir:
```bash
ssh -L 3000:127.0.0.1:3000 ubuntu@SERVER_IP
```

## Log kaynakları
- Caddy access: `deploy/logs/access.log`
- App log: `backend/data/app.log`

## Not
Grafana’yı doğrudan internete açma. Eğer açacaksan:
- IP allowlist + Basic Auth + güçlü şifre
- mümkünse VPN / ZeroTrust
