# Secrets yönetimi (Docker secrets / *_FILE)

Bu projede artık env değişkenleri **NAME_FILE** şeklinde dosyadan da okunabilir.

Örnek:
- `OPENAI_API_KEY_FILE=/run/secrets/openai_api_key`

Uygulama içerde:
- önce `OPENAI_API_KEY` bakar
- yoksa `OPENAI_API_KEY_FILE` path’ini okur

Bu sayede `.env` içine secret koymadan deploy edebilirsin.

---

## 1) Docker secrets ile kullan

### a) Secret dosyalarını oluştur (bu klasörde tutma önerilir)
Örnek:
```bash
mkdir -p deploy/secrets_runtime
echo -n "sk-..." > deploy/secrets_runtime/openai_api_key.txt
echo -n "..." > deploy/secrets_runtime/iyzico_secret_key.txt
```

> Bu dosyaları git’e koyma. Permissions: `chmod 600`.

### b) Compose override kullan
`deploy/docker-compose.prod.secrets.yml` dosyası örnek bir secrets konfigürasyonu içerir.

Çalıştır:
```bash
cd deploy
docker compose --env-file .env \
  -f docker-compose.prod.yml \
  -f docker-compose.prod.secrets.yml \
  up -d --build
```

---

## 2) En minimum güvenlik: .env permissions
`.env` kullanacaksan:
```bash
chmod 600 backend/.env
```

---

## 3) Secret rotasyonu
- `CLIENT_ID_SALT`, `EMAIL_HASH_SALT`, `RECOVERY_TOKEN_SECRET` gibi değerleri periyodik değiştir.
- Değiştirirken aktif token/recovery link’ler invalid olabilir (normal).
