# Playwright E2E (Smoke)

Bu klasör, uygulamanın en kritik akışının “kırılmadığını” kontrol etmek için Playwright smoke testleri içerir.

## Kurulum

1) Backend'i çalıştır:

```bash
cd backend
# .env içine OPENAI_API_KEY eklediğinden emin ol
python -m venv .venv
./.venv/Scripts/python.exe -m pip install -r requirements.txt
./.venv/Scripts/python.exe -m uvicorn main:app --reload --port 5555
```

2) E2E bağımlılıklarını kur:

```bash
cd e2e
npm install
npx playwright install
```

## Çalıştırma

```bash
cd e2e
npm test
```

## Notlar

- Testler gerçek UI akışını kullandığı için `OPENAI_API_KEY` olmadan değerlendirme adımı başarısız olabilir.
- Gerekirse sadece “başlatma” kısmını test etmek için smoke testini sadeleştirebilirsin.
