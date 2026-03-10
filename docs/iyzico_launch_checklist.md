# iyzico launch checklist

Bu dosya canlıya çıkmadan önce bakılacak kısa kontrol listesidir.

## Render env tarafı
- `PUBLIC_BASE_URL=https://...`
- `PAYMENT_PROVIDER=iyzico`
- `IYZICO_API_KEY`
- `IYZICO_SECRET_KEY`
- `IYZICO_BASE_URL`
- `PRO_PRICE_TRY`
- `BUSINESS_*` alanları
- `SUPPORT_EMAIL`
- `SMTP_*` (e-posta ile Pro anahtarı yolluyorsan)

## Site tarafı
- Ana sayfada fiyat görünür
- Ana sayfada iletişim alanı görünür
- `/about`, `/contact`, `/privacy`, `/terms`, `/refund` açık
- HTTPS aktif
- Ödeme butonu canlıda çalışıyor

## iyzico entegrasyon tarafı
- Checkout Form initialize çalışıyor
- Callback URL HTTPS
- Retrieve cevabında signature doğrulanıyor
- `fraudStatus == 1` olmadan Pro erişim verilmiyor

## Başvuru öncesi insan işi
- Ticari unvan / vergi / MERSİS / adres gerçek değerlerle doldur
- Yasal metinleri kendi iş modeline göre gözden geçir
- Gerekli evrakları hazırla

## Sandbox bilgileri
- Sandbox hesap aç: https://sandbox-merchant.iyzipay.com/auth/register
- API / Secret key: merchant panel -> Settings / Company Settings
- Callback URL için HTTPS kullan
