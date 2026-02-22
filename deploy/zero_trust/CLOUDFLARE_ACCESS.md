# Zero-Trust Admin (Cloudflare Access / Zero Trust)

Bu doküman Cloudflare kullanıyorsan admin paneli internete açmadan (ya da çok sıkı kısıtlayarak) yönetmen için.

## Neden?
- BasicAuth + IP allowlist çok iyi, ama IP’lerin değişebilir.
- Cloudflare Access ile admin sayfasına **kimlik doğrulama** (Google/GitHub/OTP) katmanı eklenir.

---

## Seçenek 1 (kolay): Cloudflare Access + origin’i Cloudflare IP’lerine kilitle

1) Domain’ini Cloudflare’a al ve proxy’yi (turuncu bulut) aç.
2) Cloudflare Zero Trust → Access → Applications:
   - Self-hosted application oluştur
   - URL: `https://<DOMAIN>/admin/*`
   - Policy: sadece senin kullanıcı hesabın (veya küçük bir grup) erişsin
3) Origin bypass’ı önle:
   - Sunucuda UFW ile 80/443’ü **sadece Cloudflare IP bloklarından** izin ver
   - Böylece biri doğrudan sunucunun IP’sine gitse bile erişemez

> Cloudflare IP blokları zamanla güncellenir. Bu yüzden UFW’yi otomatik güncellemek gerekir.

---

## Seçenek 2 (en güvenlisi): Cloudflare Tunnel (origin’i tamamen gizle)

Cloudflare Tunnel ile:
- Sunucuda inbound 80/443 açmazsın
- `cloudflared` outbound bağlantı kurar ve trafiği içeriden servis eder
- Dışarıdan port taramasıyla servis görünmez

Genel adımlar:
1) Sunucuya cloudflared kur
2) Cloudflare Dashboard’dan tunnel oluştur
3) Public hostname’i `http://localhost:80` veya Caddy’ye yönlendir
4) UFW’de 80/443’ü kapat (istersen tamamen)

Bu projede en pratik kurgu:
- App + Caddy localde çalışsın
- Cloudflared dışarıya yayınlasın
- Admin paneli için Access policy uygula

---

## Pratik öneri

Public launch için en sağlam kombinasyon:
- Public site: Cloudflare proxy (WAF + rate limit)
- Admin: Cloudflare Access **veya** Tailscale + localhost port
- Origin: Cloudflare Tunnel ya da en azından Cloudflare IP allowlist

> Bu sayede “origin IP’yi bulup bypass” saldırısı büyük ölçüde kapanır.
