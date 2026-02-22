# SQLite → Postgres geçiş planı (önerilen)

Bu proje MVP olarak SQLite ile başladı; public launch sonrası trafik/abonelik artınca
**blue/green deploy** ve **concurrency** için Postgres’e geçmek büyük rahatlık sağlar.

> Güvenlik açısından “Postgres = daha güvenli” değildir; ama **operasyonel dayanıklılığı** arttırır.

---

## 0) Ne zaman geçmeli?
- Aynı anda birden fazla app instance çalıştırmak istiyorsan (blue/green)
- DB lock / WAL büyümesi / IO beklemeleri görüyorsan
- Backup/restore süreleri uzadıysa

---

## 1) Hedef mimari
- `postgres` container (ya da managed Postgres)
- App: DB connection string env ile
- Migration: Alembic (uzun vadede) ya da SQL migrations

---

## 2) Docker compose ile local Postgres

Örnek dosya: `deploy/postgres/docker-compose.postgres.yml`

Çalıştır:
```bash
cd deploy/postgres
docker compose up -d
```

---

## 3) Veri taşıma (basit yaklaşım)

### A) Şema oluştur
- Postgres’te tabloları oluştur (migrations)

### B) SQLite export
Basit export:
```bash
sqlite3 backend/data/usage.db .dump > usage.sql
```

> Not: `.dump` dosyası Postgres ile bire bir uyumlu değildir. Genelde dönüştürme gerekir.

### C) En pratik araç: pgloader
`pgloader` SQLite → Postgres dönüşümünü otomatik yapabilir.

Örnek:
```bash
pgloader sqlite:///path/to/usage.db postgresql://user:pass@host:5432/sanal
```

### D) Repo içi taşıma scripti (önerilen)
Bu repo ayrıca SQLite → Postgres için **tek seferlik** bir script içerir:

- `backend/db_transfer_sqlite_to_postgres.py`

Dokümantasyon:
- `docs/internal/SQLITE_TO_POSTGRES_TRANSFER.md`

Bu yöntem `.dump`/`pgloader` yerine **uygulamanın kullandığı tablo yapısına** uygun şekilde
UPSERT yapar ve daha kontrollüdür.

---

## 4) App tarafı (bu repo)

Bu repo artık **Postgres'i native** destekliyor.

Seçenekler:
1) **DB_ENGINE=postgres** + PG_* env (veya direkt **DATABASE_URL**) ile çalıştır.
2) Migration runner: `python backend/db_migrate.py --engine postgres --dir backend/migrations/postgres`
3) Prod compose: `deploy/docker-compose.prod.pg.yml` (DB internal network + migrate servisi)

Uzun vadede şema karmaşıklaşırsa SQLAlchemy/Alembic'e geçmek yine mantıklı.

---

## 5) Rollback stratejisi
- Migration sonrası rollback gerekiyorsa: Postgres snapshot/backup’tan geri dön.
- SQLite’dan Postgres’e geçişte “çift yazma” (dual-write) kısa süreli çözüm olabilir.

---

## 6) Güvenlik notları
- Postgres’i internete açma. Sadece internal network.
- Strong password + SCRAM.
- Regular patching.
- Backup encryption (opsiyonel).
