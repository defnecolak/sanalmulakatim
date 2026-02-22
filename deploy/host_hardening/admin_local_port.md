# Admin paneli internete hiç açmama (en güvenli yöntem)

Bu proje bir **security panel** (`/admin/security`) içeriyor.

En güvenli yaklaşım:
- Admin paneli **public domain üzerinden hiç servis etme**
- Sadece **localhost:8081** gibi bir porta bind et
- Erişimi **SSH tunnel** ile yap

Bu repo bunu opsiyonel olarak destekler.

---

## 1) Prod compose override ile localhost port aç

`deploy/docker-compose.prod.admin-local.yml` dosyası Caddy container’ında 8081 portunu **sadece 127.0.0.1** üzerinden host’a map eder:

- Host tarafında: `127.0.0.1:8081`
- İnternetten erişilemez

Kullanım:

```bash
cd deploy
# normal prod compose + admin-local override
docker compose --env-file .env \
  -f docker-compose.prod.yml \
  -f docker-compose.prod.admin-local.yml \
  up -d --build
```

---

## 2) SSH tunnel ile eriş

Kendi bilgisayarından:

```bash
ssh -L 8081:127.0.0.1:8081 ubuntu@SUNUCU_IP
```

Sonra tarayıcıda:

- `http://127.0.0.1:8081/admin/security`

> Basic Auth yine çalışır. (Caddyfile’da tanımlı.)

---

## 3) Notlar

- Bu yöntem Cloudflare/Tailscale kullanmasan bile en güvenlisidir.
- Admin panel erişimi için artık public domain’de IP allowlist ayarıyla uğraşmana gerek kalmaz.
