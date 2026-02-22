# SQLite → Postgres veri taşıma (repo içi script)

Bu repo, SQLite (MVP) → Postgres (prod) geçişi için **tek seferlik** bir taşıma scripti içerir.

Script dosyası:
- `backend/db_transfer_sqlite_to_postgres.py`

Taşınan veriler (mümkünse)
- `usage_daily`, `usage_total` (deneme/kullanım sayacı)
- `pro_tokens`, `payment_orders`
- `email_token_links`, `recovery_links`, `delete_links`
- `ip_bans` (ban list)
- `security_events` (admin security panel geçmişi)

> Not: `security_events` için varsayılan davranış **temkinli**: hedef tabloda veri varsa kopyalamaz (duplicate riskini azaltmak için).

---

## Önerilen akış (prod)

1) **Trafiği durdur / switch et**
- Blue/green kullanıyorsan önce trafiği diğer renge geçir.
- Ya da kısa bir maintenance ile app'i durdur.

2) **Postgres hazır olsun**
- `deploy/docker-compose.prod.pg.yml` ile Postgres + migrate servisini ayağa kaldır.
- `migrate` servisi tabloları otomatik oluşturur.

3) **Taşıma scriptini çalıştır (hardened öneri)**

Bu sürümde script:
- Taşıma sonrası **row count doğrulaması** yapar (SQLite vs Postgres)
- İstersen SQLite DB’nin **tutarlı snapshot** arşivini alır (sqlite backup API ile)
- İstersen eski SQLite DB’yi **read-only** yapar (yanlışlıkla yazma olmasın diye)

### A) Docker içinde (önerilen)

```bash
cd deploy
./runbook/transfer_sqlite_to_postgres.sh
```

Bu runbook, container içinde şunları yapar:
- `--migrate`
- `--strict-counts` (sayım uyuşmazsa fail)
- `--archive-sqlite` (deploy/backups içine snapshot)
- `--set-readonly` (eski sqlite dosyası read-only)

### B) Host üzerinde

```bash
python backend/db_transfer_sqlite_to_postgres.py \
  --sqlite backend/data/usage.db \
  --pg-url "$DATABASE_URL" \
  --migrate \
  --strict-counts \
  --archive-sqlite \
  --set-readonly
```

---

## Dry-run (sadece sayım)

Postgres'e bağlanmadan, SQLite içindeki satır sayılarını görmek için:

```bash
python backend/db_transfer_sqlite_to_postgres.py --sqlite backend/data/usage.db --dry-run
```

---

## Duplicates / tekrar çalıştırma

Bu scripti **genelde 1 kez** çalıştırmalısın.

- Çoğu tabloda `ON CONFLICT DO UPDATE` var → tekrar çalıştırırsan genelde idempotent olur.
- **security_events** append-only olduğu için tekrar import duplicates üretebilir.

Temiz import (dikkat!):

```bash
python backend/db_transfer_sqlite_to_postgres.py --sqlite backend/data/usage.db --migrate --truncate
```

---

## Başarı kontrolü

### 1) Otomatik: kritik akış smoke testi

Taşıma sonrası, app Postgres ile ayaktayken:

```bash
cd deploy
./runbook/smoke_critical_flows.sh
```

Bu smoke:
- `/api/healthz` ve `/api/usage`
- Pro token doğrulaması
- Recovery consume (`/api/pro/recovery/consume`)
- Privacy delete confirm (`/api/privacy/delete/confirm`)

> Not: E-posta göndermeden test eder. Test için DB’ye küçük, etiketli kayıtlar ekler ve temizlik yapar.

### 2) Operatör checklist

- Admin panel → security events görünüyor mu?
- Free deneme sayaçları beklediğin gibi mi?
- Pro token / recovery / delete akışları hatasız mı?

> En iyi pratik: taşıma sonrası `deploy/runbook/transfer_verify_smoke.sh` ile “transfer + restart + smoke” tek komut.
