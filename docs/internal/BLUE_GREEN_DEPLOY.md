# Blue/Green Deploy (Immutable)

Bu klasör deploy/bluegreen içindeki script’leri kullanır.

⚠️ Not: SQLite ile “tam zero-downtime” zor olabilir.
Bu proje SQLite kullanıyorsa, iki instance aynı anda DB’ye yazmaya çalışmasın.
Gerçek blue/green için uzun vadede Postgres önerilir.

## Akış
1) Yeni release için image build (tag’li)
2) Inactive renk üzerinde ayağa kaldır (healthz kontrol)
3) (Varsa) DB migration uygula (offline)
4) Caddy upstream’i yeni renge switch et (reload)
5) Post-switch smoke test
6) Eski rengi durdur

## Rollback
- Caddy’yi eski renge çevir
- Eski container’ı tekrar up et
