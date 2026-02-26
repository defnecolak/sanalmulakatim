# Production Deploy (VPS + Docker Compose + Caddy HTTPS)

Bu doküman, projeyi **tek sunucu** üzerinde (Ubuntu/Debian) Docker ile ayağa kaldırmak içindir.
Caddy otomatik HTTPS (Let's Encrypt) alır.

> Not: Repo içinde `docs/internal/` klasörü operasyon/runbook içerir.
> Repo’yu public yapacaksan bu klasörü public’e koyma.

## 0) Gerekenler
- Bir **domain** (ör. `sanalmulakatim.com`)
- Bir **VPS** (Ubuntu 22.04 önerilir)
- VPS IP adresine DNS A kaydı
- Sunucuda 80/443 portları açık

## 1) Sunucuya Docker kur (Ubuntu)
```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

İsteğe bağlı: kullanıcıyı docker grubuna al:
```bash
sudo usermod -aG docker $USER
# sonra SSH'dan çık-gir
```

## 2) Projeyi sunucuya koy
Zip’i sunucuya kopyala ve aç.
Klasör yapısı şöyle olmalı:

```
interview-sim-lite-launch/
  backend/
  deploy/
  Dockerfile
```

## 3) Backend ENV ayarla (backend/.env)
```bash
cd interview-sim-lite-launch
cp backend/.env.example backend/.env
nano backend/.env
```

Production için kritik:
- `OPENAI_API_KEY=...`
- `PUBLIC_BASE_URL=https://sanalmulakatim.com`
- `SUPPORT_EMAIL=semi.ozgen@sanalmulakatim.com`
- Limitler: `FREE_EVALS_TOTAL`, `FREE_OCR_PER_DAY`, endpoint bazlı rate limit’ler
- Ödeme: `PAYMENT_PROVIDER=iyzico` + `IYZICO_*`
- SMTP: `SMTP_*` (recovery + delete confirm mail için)

## 4) Caddy ENV ayarla (deploy/.env)
```bash
cp deploy/.env.prod.example deploy/.env
nano deploy/.env
```

İçini doldur:
- `DOMAIN=sanalmulakatim.com`
- `ACME_EMAIL=...`

### Admin Security Panel (çok önerilir)
Bu projede `/admin/security` ve `/api/admin/*` için **çok katmanlı** koruma var:
- Caddy: IP allowlist + Basic Auth (allowlist dışına 404)
- Backend: `x-admin-key` (opsiyonel 2FA/TOTP)
- Defence-in-depth: `ADMIN_EDGE_TOKEN` (Caddy → backend header)

## 5) DNS ayarı
Domain panelinden:
- `A` kaydı: `@` → VPS_IP
- `www` için istersen `A`: `www` → VPS_IP

## 6) Çalıştır (tek komut)
### Seçenek A: SQLite (tek instance / en basit)
```bash
docker compose --env-file deploy/.env -f deploy/docker-compose.prod.yml up -d --build
```

### Seçenek B: Postgres (blue/green + multi-instance için önerilir)
Postgres deploy dosyası DB'yi internetten izole eder (internal network) ve
ayrıca otomatik migration runner (`migrate` servisi) çalıştırır.

Önce `deploy/.env` içine PG bilgilerini ekle:
- `PG_DB=sanal_mulakatim`
- `PG_USER=sanal`
- `PG_PASSWORD=...` (prod'da güçlü)

Sonra:
```bash
docker compose --env-file deploy/.env -f deploy/docker-compose.prod.pg.yml up -d --build
```

Log:
```bash
docker compose --env-file deploy/.env -f deploy/docker-compose.prod.yml logs -f --tail=200
```

Postgres compose ile log:
```bash
docker compose --env-file deploy/.env -f deploy/docker-compose.prod.pg.yml logs -f --tail=200
```

## 7) Güncelleme
Basit (downtime çok az, ama “immutable blue/green” değil):
```bash
docker compose --env-file deploy/.env -f deploy/docker-compose.prod.yml up -d --build
```

Immutable Blue/Green için: `deploy/bluegreen/` klasörüne bak.

## 8) Healthcheck
```bash
curl -fsS https://DOMAIN/api/healthz
```

## 9) Backup / Restore
Backup’lar: `deploy/backups/`

Backup:
```bash
./deploy/backup.sh
```

Integrity verify:
```bash
./deploy/verify_backup.sh ./deploy/backups/backup-....tar.gz
```

Restore:
```bash
./deploy/restore.sh ./deploy/backups/backup-....tar.gz
docker compose --env-file deploy/.env -f deploy/docker-compose.prod.yml up -d
```

### systemd timer (cron yerine)
`deploy/systemd/` içindeki unit’leri /etc/systemd/system/ altına kopyalayıp aktif edebilirsin.
Detay: `docs/internal/BACKUP_RESTORE.md`

## 10) Merkezi log (Loki)
`deploy/observability/loki/` altında basit Loki+Promtail+Grafana stack var.
Detay: `docs/internal/OBSERVABILITY_LOKI.md`

## 11) Cloudflare export/import
`deploy/cloudflare/` scriptleri ile zone ruleset’leri export/import edebilirsin.
Detay: `docs/internal/CLOUDFLARE_WAF.md`

## 12) Docker secrets (önerilen)

Prod’da secret’ları `.env` içinde taşımak yerine Docker secrets kullanabilirsin.

- Detay: `deploy/secrets/README.md`
- Örnek override: `deploy/docker-compose.prod.secrets.yml`

Örnek:
```bash
docker compose --env-file deploy/.env \
  -f deploy/docker-compose.prod.yml \
  -f deploy/docker-compose.prod.secrets.yml \
  up -d --build
```

## 13) Admin paneli internete hiç açma (localhost port + SSH tunnel)

En güvenlisi:
- Caddy’de admin’i ayrı bir internal porttan (8081) servis etmek
- host’ta sadece `127.0.0.1:8081` olarak publish etmek
- SSH tunnel ile erişmek

Detay: `deploy/host_hardening/admin_local_port.md`

## 14) Host hardening + Zero Trust

- UFW/SSH/fail2ban/unattended upgrades: `deploy/host_hardening/README.md`
- Tailscale: `deploy/zero_trust/TAILSCALE.md`
- Cloudflare Access/Tunnel: `deploy/zero_trust/CLOUDFLARE_ACCESS.md`
