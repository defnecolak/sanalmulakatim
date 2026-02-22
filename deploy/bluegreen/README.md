# Blue/Green Deploy

Bu klasör “immutable-ish” blue/green deploy için örnek verir.

## Neden?
- Yeni sürümü ayrı container’da ayağa kaldır
- Healthz geçince Caddy upstream’i switch et
- Gerekirse rollback çok hızlı olur (eski renge switch)

## SQLite Notu
Bu projede SQLite varsa, iki instance aynı DB’ye yazmaya çalışmasın.
Bu nedenle green “warmup” sırasında `SKIP_STARTUP_CLEANUP=1` ile yazma riskini azaltıyoruz.
Gerçek zero-downtime için Postgres önerilir.

## Çalıştırma
```bash
cd deploy
cp .env.prod.example .env
# .env doldur

docker compose --env-file .env -f bluegreen/docker-compose.bluegreen.yml up -d --build
```

Yeni sürüm deploy örneği:
```bash
./bluegreen/deploy.sh green 2026-02-20-rc1
```

Rollback:
```bash
./bluegreen/switch.sh blue
```
