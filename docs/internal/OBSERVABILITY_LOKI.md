# Merkezi Log (Grafana Loki)

Bu repo `deploy/observability/loki` altında Loki+Promtail+Grafana ile basit log merkezi sağlar.

## Başlatma
```bash
docker compose -f deploy/observability/loki/docker-compose.loki.yml up -d
```

Grafana: http://SERVER:3000
- default: admin / admin (ilk login’de değiştir)

## Ne toplanıyor?
- Caddy access log (JSON): `deploy/logs/access.log`
- App log: `backend/data/app.log`

## Güvenlik
- Grafana’yı public internete açma
- IP allowlist / basic auth / VPN önerilir
