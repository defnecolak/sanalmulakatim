# DB Migration Plan

Bu projede SQLite ile küçük ölçekli bir DB var.
Ama production’da “schema değişimi” yönetilmezse deploy kabusa döner.

## Kural 1: Additive migrations
- Sütun ekle, tablo ekle: OK
- Sütun silme/rename: önce yeni sütun ekle, eskiyi bir süre daha tut, sonra temizle

## Kural 2: Migrations runner
`backend/db_migrate.py`:
- `schema_migrations` tablosu tutar
- SQLite: `backend/migrations/sql/*.sql` dosyalarını sırayla uygular
- Postgres: `backend/migrations/postgres/*.sql` dosyalarını sırayla uygular

Engine seçimi:
- `DATABASE_URL=postgresql://...` varsa otomatik Postgres
- veya `DB_ENGINE=postgres` + `PG_*` değişkenleri

## Kural 3: Blue/Green + DB
- Schema değişimi varsa:
  - önce migration uygula
  - sonra yeni version deploy
- SQLite concurrency sınırları var; büyük değişimde maintenance window düşün.

## Postgres’e geçiş (opsiyonel)
- Bu proje artık Postgres'i *native* destekliyor.
- Prod deploy için `deploy/docker-compose.prod.pg.yml` kullan.
- Blue/green ve çoklu instance için Postgres büyük fark yaratır.
