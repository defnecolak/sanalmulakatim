# Sanal Mülakatım (Launch Lite)

Odak: **Tek soru akışı • CV ile kişiselleştirme • Ses → Yazı**

Bu sürüm “launch”a yakın olsun diye şu parçaları da içerir:

- ✅ **Landing + fiyatlandırma** (/)  
- ✅ **Uygulama** (/app)  
- ✅ **Gizlilik / Şartlar** (/privacy, /terms)  
- ✅ **Rate limit + kullanım limitleri** (FREE plan)  
- ✅ **Pro anahtarı (manual)** + **Stripe checkout (opsiyonel)**  
- ✅ PDF metin okuma + **taranmış PDF için OCR** (limitli)  
- ✅ Log dosyası (`backend/data/app.log`) + opsiyonel Sentry
- ✅ Ödeme durumu takibi + idempotency (callback tekrar gelse bile token 1 kez üretilir)
- ✅ Pro anahtar kurtarma (magic link) + veri silme sayfası

## Kurulum (Windows PowerShell)

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
copy .env.example .env
notepad .env
.\.venv\Scripts\python.exe -m uvicorn main:app --reload --port 5555
```

- Landing: http://localhost:5555  
- Uygulama: http://localhost:5555/app  

## OpenAI API Key
`.env` dosyasında:

```
OPENAI_API_KEY=sk-...
```

## Postgres (opsiyonel ama prod için önerilir)
SQLite tek instance için süper pratik. Ama public launch'ta blue/green ve birden fazla instance
çalıştırmak istersen Postgres daha sağlıklı.

`.env` içinde şu iki yoldan biri:

**Yol A (URL):**
```env
DATABASE_URL=postgresql://USER:PASS@HOST:5432/DB
```

**Yol B (parçalar):**
```env
DB_ENGINE=postgres
PG_HOST=postgres
PG_PORT=5432
PG_DB=sanal_mulakatim
PG_USER=sanal
PG_PASSWORD=...
```

Migration:
```bash
python backend/db_migrate.py --engine postgres --dir backend/migrations/postgres
```

Prod compose (DB internetten izole + otomatik migration):
```bash
docker compose --env-file deploy/.env.example -f deploy/docker-compose.prod.pg.yml up -d --build
```

## Limitler (Free plan)
`.env` içinden ayarlanır:

- `FREE_EVALS_TOTAL` (toplam deneme)
- `FREE_TRANSCRIBES_PER_DAY` (varsayılan 0: sınırsız)
- `FREE_OCR_PER_DAY`
- `RATE_LIMIT_PER_MINUTE`

Tarayıcı her istekte **X-Client-ID** gönderir (localStorage’dan). Böylece aynı IP arkasında bile limitler karışmaz.

## Pro anahtarı (manual)
`.env` içine:

```
PRO_TOKENS=pro_abc123,pro_def456
```

Uygulamada “Pro Anahtarı” alanına girince limitler kalkar.

## Pro anahtar kurtarma (magic link)
Ödemeden sonra `/success` sayfasında Pro anahtarı gösterilir ve **istersen e-postana gönderme** seçeneği vardır.

Eğer anahtarı kaybedersen:

- Kurtarma sayfası: `.../recover`
- E-postanı gir → “Kurtarma linki gönder”
- Gelen tek-kullanımlık linki aç → kayıtlı Pro anahtar(lar)ını gör

> Not: Kurtarma sistemi, **daha önce anahtarı e-posta ile gönderdiysen** çalışır (e-postayı hashleyerek eşleştirir).

## Veri saklama & silme

- `DATA_RETENTION_DAYS` (varsayılan 90): bazı teknik kayıtlar (limit sayacı, ödeme denemeleri, kurtarma token’ları) bu süreyi geçince temizlenir.
- Self-service silme sayfası: `.../delete` (**e-posta onaylı**)

Silme akışı iki adımlı:
1) E-posta gir → sistem tek-kullanımlık **onay linki** gönderir
2) Linke tıkla → silme/anonimleştirme işlemi gerçekleşir

Bu işlem e-postaya bağlı kayıtları anonimleştirir (e-postayı DB’den kaldırır) ve kurtarma eşleşmesini siler.

## Stripe (opsiyonel)
`.env` içine:

```
STRIPE_SECRET_KEY=...
STRIPE_PRICE_ID=...
STRIPE_WEBHOOK_SECRET=...
PUBLIC_BASE_URL=https://senindomainin.com
```

Akış:
1) Landing’de “Pro’ya Geç” → Stripe Checkout  
2) Success URL: `/success?session_id=...`  
3) Webhook `checkout.session.completed` gelince token üretilir  
4) Success sayfası `/api/billing/redeem` ile token’ı çeker ve tarayıcıya kaydeder

> Not: Stripe webhook’u production’da zorunlu. Local’da Stripe CLI ile test edebilirsin.


## Ödeme sağlayıcısı seçimi
`.env` içinde:

```
PAYMENT_PROVIDER=stripe|iyzico
```

> `PAYMENT_PROVIDER` boşsa: iyzico ayarlıysa iyzico, değilse Stripe seçilir.

## iyzico (Türkiye için)
`.env` içine şunları gir:

```
PAYMENT_PROVIDER=iyzico
IYZICO_API_KEY=sandbox-...
IYZICO_SECRET_KEY=sandbox-...
IYZICO_BASE_URL=https://sandbox-api.iyzipay.com
PRO_PRICE_TRY=199.0
PUBLIC_BASE_URL=https://senindomainin.com
```

Akış:
1) Landing’de “Pro’ya Geç” → iyzico ödeme sayfası açılır
2) Ödeme bitince iyzico, `callbackUrl` adresine **POST** ile `token` yollar
3) Backend `CF-Retrieve` ile sonucu doğrular ve Pro anahtarı üretir
4) Kullanıcı `/success?provider=iyzico&ref=...` sayfasında anahtarını görür

> Not: iyzico Checkout Form `callbackUrl` için **HTTPS / SSL** bekler. Local test için ngrok gibi bir https tüneli kullanman gerekir.

## PDF
- PDF seçince otomatik okunur.
- Metin çıkmazsa taranmış PDF kabul edilip OCR denenir (OpenAI ile).
- Limitler: `MAX_PDF_MB`, `PDF_MAX_PAGES`, `OCR_MAX_PAGES`

> Not: İçerik eğitim amaçlıdır; gerçek klinik karar yerine geçmez.


## Production Deploy (VPS)
Detaylı yönerge: `deploy/README_DEPLOY.md`

## E2E (Playwright) smoke test

`e2e/` klasörü, “start → answer → evaluate → next” akışını otomatik test eder.

```bash
cd e2e
npm install
npx playwright install
npm test
```


## İletişim / İade (Launch için gerekli sayfalar)

- `/contact` → iletişim / destek
- `/refund` → iade politikası şablonu
- Footer linkleri: Ana Sayfa / Gizlilik / Şartlar / İade / İletişim / Uygulama

> Not: Metinler şablon niteliğindedir. Üretimde kendi mevzuatınıza göre gözden geçirin.

## Pro anahtarını e-posta ile gönderme (opsiyonel)

Satın alma sonrası **/success** sayfasında “E-postama Gönder” butonu var.

SMTP ayarlamak için `backend/.env` içine şunları gir:

```bash
# örnek
SUPPORT_EMAIL=support@senindomainin.com
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=seninmailin@gmail.com
SMTP_PASS=GMAIL_APP_PASSWORD
SMTP_FROM=support@senindomainin.com
SMTP_FROM_NAME=Sanal Mülakatım
SMTP_USE_TLS=1
SMTP_USE_SSL=0
```

Gmail kullanıyorsan “App Password” gerekir (normal şifreyle çalışmaz).



## Deploy komutu (Windows notu)

`deploy/.env.example` dosyasını bulması için komutu **proje kökünde** çalıştır:

```bash
docker compose --env-file deploy/.env.example -f deploy/docker-compose.prod.yml up -d --build
```

`backend` klasörünün içinde çalıştırırsan `deploy/.env.example` yolunu bulamayabilir.



## Testler (Debugging / Smoke)
Projeyi “düzgün çalışıyor mu?” diye hızlı kontrol etmek için pytest testleri eklenmiştir.

Kurulum:
```powershell
cd backend
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
```

Çalıştırma:
```powershell
cd backend
.\.venv\Scripts\python.exe -m pytest -q
```

Testler şunları doğrular:
- /api/health çalışıyor
- iyzico checkout URL üretiliyor (mock ile)
- iyzico callback → token üretimi + redeem
- Ödeme sonrası otomatik e-posta (mock SMTP ile)
- Hedef rol kilidi (CV farklı alan olsa bile prompt kuralı)

> Not: Testler **gerçek iyzico/OpenAI çağrısı yapmaz** (mock kullanır).

## Public Launch / Güvenlik

Public’e çıkmadan önce: `SECURITY_CHECKLIST.md` dosyasını oku ve `deploy/smoke_public.*` ile smoke test koş.


### Security Panel (Prod Debug)

Prod’da “log gibi okunur” bir görünüm için basit bir panel eklendi:

- UI: **/admin/security**
- API:
  - **/api/admin/security/events?limit=200**
  - **/api/admin/security/summary?minutes=60**

Panel, API’ye **X-Admin-Key** header’ı ile bağlanır. Bu key:

- `.env` içinde **ADMIN_STATUS_KEY** olarak belirlenir.

> Not: Panel **raw IP tutmaz**; “ban_key / client_id” hash’leriyle korelasyon yapar.

### Admin Panel’ini İnternetten Saklama (Caddy Basic Auth + IP Allowlist)

Prod’da **/admin/security** ve **/api/admin/security/** path’lerini “internetin geri kalanından” gizlemek için Caddy tarafında iki katman koyduk:

1) **IP allowlist** (sadece senin IP/CIDR’ların)
2) Üstüne **Basic Auth** (kullanıcı+parola)

İlgili değişkenler:

- `deploy/.env.example.prod` içinde:
  - `ADMIN_ALLOW_IPS="1.2.3.4 5.6.7.0/24"`
  - `ADMIN_BASIC_USER=admin`
  - `ADMIN_BASIC_PASS_HASH=<bcrypt>`

Parola hash’i üretmek için (lokalde Docker varsa):

```bash
docker run --rm caddy:2 caddy hash-password --plaintext "SIFREN"
```

Ek savunma: backend tarafında da (opsiyonel) IP allowlist var:

- `backend/.env` içinde `ADMIN_PANEL_ALLOW_IPS="..."` (boşsa devre dışı)

### CAPTCHA (Cloudflare Turnstile)

“E-posta tetikleyen” endpoint’leri (Pro kurtarma linki / veri silme onay linki) bot/spam’a açık olabilir. İstersen Cloudflare Turnstile ile iki endpoint’te CAPTCHA zorunluluğu açabilirsin.

Backend `.../api/public_config` üzerinden sadece **site key** yayınlar; secret key asla client’a gitmez.

`.env` (backend) değişkenleri:

```env
CAPTCHA_PROVIDER=turnstile
TURNSTILE_SITE_KEY=...
TURNSTILE_SECRET_KEY=...
CAPTCHA_FAIL_OPEN=0
CAPTCHA_REQUIRED_EMAIL=1
BAN_STRIKE_WEIGHT_CAPTCHA=5
```

### Endpoint-bazlı Rate Limit

Eski `RATE_LIMIT_PER_MINUTE` hâlâ varsayılan fallback’tir. İstersen key bazında override edebilirsin:

- `RATE_LIMIT_EVAL_PER_MIN` (örn. evaluate)
- `RATE_LIMIT_BILLING_PER_MIN` (örn. create_checkout)

Pro için:

- `RATE_LIMIT_EVAL_PER_MIN_PRO`
- `RATE_LIMIT_BILLING_PER_MIN_PRO`

Pro kullanıcılarının rate limit’i tamamen bypass etmesini istersen:

- `PRO_BYPASS_RATE_LIMIT=1`

### Strike Weight (Ban Sistemi)

- `BAN_STRIKE_WEIGHT_WAF=5` (WAF tetiklenmesi)
- `BAN_STRIKE_WEIGHT_429=2` (rate limit 429)
- `BAN_STRIKE_WEIGHT_DEFAULT=1` (diğer strike status’lar)


### Secrets (Docker secrets / *_FILE)

Prod’da `.env` içinde secret tutmak yerine **Docker secrets** (dosya) kullanabilirsin.

- Dokümantasyon: `deploy/secrets/README.md`
- Örnek compose override: `deploy/docker-compose.prod.secrets.yml`

Uygulama artık `OPENAI_API_KEY_FILE=/run/secrets/openai_api_key` gibi değişkenleri okuyabilir.

### Zero-Trust Admin (Tailscale / Cloudflare)

Admin panelini internete açmamak en güvenlisi.

- Local-only admin port + SSH tunnel: `deploy/host_hardening/admin_local_port.md`
- Tailscale önerisi: `deploy/zero_trust/TAILSCALE.md`
- Cloudflare Access/Tunnel önerisi: `deploy/zero_trust/CLOUDFLARE_ACCESS.md`

### Host Hardening (UFW / SSH / fail2ban)

VPS seviyesinde sertleştirme için:
- `deploy/host_hardening/README.md`

> ⚠️ Repo public olacaksa `docs/internal/` klasörünü yayınlama.
