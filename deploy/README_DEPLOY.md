# Production Deploy (VPS + Docker Compose + Caddy HTTPS)

Bu dosya, projeyi **tek sunucu** üzerinde (Ubuntu/Debian) Docker ile ayağa kaldırmak içindir.
Caddy otomatik HTTPS (Let's Encrypt) alır.

## 0) Gerekenler
- Bir **domain** (ör. `senindomainin.com`)
- Bir **VPS** (Ubuntu 22.04 önerilir)
- VPS IP adresine DNS A kaydı
- Sunucuda 80/443 portları açık

## 1) Sunucuya Docker kur
Ubuntu için hızlı kurulum:

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
En basit: bu repo/zip'i sunucuya kopyala ve aç.
Örnek:

```bash
mkdir -p ~/interview-sim
cd ~/interview-sim
# buraya dosyaları kopyala
```

Klasör yapısı şöyle olmalı:

```
interview-sim-lite-launch/
  backend/
  deploy/
  Dockerfile
```

## 3) Uygulama ENV ayarla (backend/.env)
`backend/.env.example` dosyasını kopyalayıp düzenle:

```bash
cd interview-sim-lite-launch
cp backend/.env.example backend/.env
nano backend/.env
```

Production için kritik satırlar:
- `OPENAI_API_KEY=...`
- `PUBLIC_BASE_URL=https://senindomainin.com`
- Limitler: `FREE_EVALS_TOTAL`, `FREE_OCR_PER_DAY`, `RATE_LIMIT_PER_MINUTE` vs
- Stripe kullanacaksan: `STRIPE_SECRET_KEY`, `STRIPE_PRICE_ID`, `STRIPE_WEBHOOK_SECRET`
- iyzico kullanacaksan: `PAYMENT_PROVIDER=iyzico` + `IYZICO_API_KEY`, `IYZICO_SECRET_KEY`, `IYZICO_BASE_URL`, `PRO_PRICE_TRY`

## 4) Caddy ENV ayarla (deploy/.env)
```bash
cp deploy/.env.prod.example deploy/.env
nano deploy/.env
```

İçini doldur:
- `DOMAIN=senindomainin.com`
- `ACME_EMAIL=...`

### Admin Güvenlik Paneli (opsiyonel ama önerilir)
Bu projede `/admin/security` ve `/api/admin/*` için **çok katmanlı** koruma var:
- Caddy tarafında IP allowlist + Basic Auth
- Backend tarafında `x-admin-key` (ve opsiyonel `x-admin-2fa`)
- Ek olarak Caddy'nin backend'e enjekte ettiği `ADMIN_EDGE_TOKEN` header'ı (defence-in-depth)

Yapılacaklar:
- `backend/.env` içine:
  - `ADMIN_STATUS_KEY=...` (uzun, rastgele)
  - (opsiyonel) `ADMIN_2FA_KEY=...`
- `deploy/.env` içine:
  - `ADMIN_EDGE_TOKEN=...` (uzun, rastgele)
  - `ADMIN_ALLOW_IPS=...` (sadece kendi IP'lerin)
  - `ADMIN_BASIC_USER` / `ADMIN_BASIC_PASS_HASH`

> Not: `ADMIN_EDGE_TOKEN` hem Caddy tarafında header olarak gönderilir hem de backend aynı değeri bekler.


## 5) DNS ayarı
Domain panelinden:
- `A` kaydı: `@` → VPS_IP
- İstersen `www` için de `A`: `www` → VPS_IP

DNS yayılımı bazen 5-30 dk sürer.

## 6) Çalıştır (tek komut)
```bash
cd ~/interview-sim/interview-sim-lite-launch
docker compose --env-file deploy/.env -f deploy/docker-compose.prod.yml up -d --build
```

Log:
```bash
docker compose --env-file deploy/.env -f deploy/docker-compose.prod.yml logs -f
```

## 7) Güncelleme
Yeni sürüm attıysan:
```bash
docker compose --env-file deploy/.env -f deploy/docker-compose.prod.yml up -d --build
```

## 8) Stripe Webhook (production)
Stripe dashboard'da webhook endpoint:
- `https://senindomainin.com/api/billing/webhook`

Event: `checkout.session.completed`

Local test için Stripe CLI kullanılabilir.

## 9) Troubleshooting
- HTTPS gelmiyorsa: DNS A kaydı doğru mu? 80/443 açık mı?
- 502: app container ayakta mı? `docker ps`, `docker logs`
- OpenAI hatası: backend/.env içinde key var mı? `OPENAI_API_KEY`
## 10) Healthcheck / Auto-restart
Bu compose dosyasında `app` servisi için healthcheck var.
Durum görmek için:

```bash
docker ps
docker inspect --format='{{json .State.Health}}' $(docker compose --env-file deploy/.env -f deploy/docker-compose.prod.yml ps -q app) | jq
```

## 11) Log rotation
Docker container logları `max-size` / `max-file` ile sınırlandı (json-file).
Uygulama ayrıca `backend/data/app.log` içine de log yazar.

## 12) Backup / Restore (SQLite + loglar)
SQLite ve loglar `backend/data/` altında. Hızlı backup:

```bash
./deploy/backup.sh
```

Geri yükleme:

```bash
./deploy/restore.sh ./backups/data-YYYYMMDD-HHMMSS.tar.gz
# sonra containerları restart et
docker compose --env-file deploy/.env -f deploy/docker-compose.prod.yml up -d
```

Cron ile günlük backup örneği:

```bash
crontab -e
# her gece 03:10
10 3 * * * /bin/bash /home/ubuntu/interview-sim/interview-sim-lite-launch/deploy/backup.sh >/dev/null 2>&1
```

## 13) WAF + otomatik ban (uygulama içi)

Backend içinde düşük “false positive” hedefleyen basit bir WAF katmanı var:
- Botların sık denediği path’leri (ör. `/wp-admin`, `/.env`, `phpmyadmin`) direkt 403’ler
- URL/query/header üzerinde bariz saldırı pattern’lerini yakalar
- Aşırı agresif denemelerde geçici ban (ban list) uygular

Ayarlar `.env` ile:

- `WAF_ENABLED=1` / `WAF_BLOCK=1`
- `BAN_ENABLED=1`, `BAN_THRESHOLD`, `BAN_WINDOW_SEC`, `BAN_TTL_SEC`

> Bu katman, “cevap/CV” gibi serbest metin alanlarını agresif şekilde taramaz.
> Amaç bot scan’lerini kesmek, gerçek kullanıcıyı yanlışlıkla engellememektir.

## 14) Fail2ban (opsiyonel)

Sunucu seviyesinde bir katman istiyorsan `deploy/fail2ban/` altındaki örnek konfigürasyonları kullanabilirsin.
Caddy erişim logunu dosyaya yazdırıyoruz (`deploy/Caddyfile`), böylece Fail2ban log üzerinden ban uygular.

Detaylar için: `deploy/fail2ban/README.md`
