# Zero-Trust Admin (Tailscale) — önerilen

Amaç: Admin paneli ve SSH erişimini **internetten tamamen ayırmak**.

Bu yöntemde:
- SSH’yi mümkünse yalnızca Tailscale üzerinden kullanırsın
- Admin panelini internete açmazsın (localhost:8081 + SSH tunnel) **veya** sadece tailnet IP’lerinden izin verirsin

---

## 1) Sunucuda Tailscale kur

Ubuntu:
```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up
```

`tailscale ip -4` ile sunucunun Tailnet IP’sini görürsün (`100.x.y.z`).

---

## 2) SSH erişimini Tailscale’e taşı (opsiyonel ama tavsiye)

### Seçenek A: Tailscale SSH (en kolayı)
```bash
sudo tailscale up --ssh
```
Sonra kendi bilgisayarından:
```bash
ssh ubuntu@SUNUCU_TAILSCALE_ADI
```

### Seçenek B: Klasik SSH + UFW ile sadece Tailscale arayüzünden izin
- UFW’de public internetten 22’yi kapat
- Sadece `tailscale0` interface üzerinden izin ver

Örnek:
```bash
sudo ufw deny 22/tcp
sudo ufw allow in on tailscale0 to any port 22 proto tcp
sudo ufw status verbose
```

> ⚠️ Kendini kilitlememek için console erişimin olsun.

---

## 3) Admin panel erişimi

### En güvenlisi: localhost port + SSH tunnel
Bu repo `deploy/docker-compose.prod.admin-local.yml` ile Caddy’de 8081’i **sadece 127.0.0.1**’e map eder.

Kendi bilgisayarından:
```bash
ssh -L 8081:127.0.0.1:8081 ubuntu@SUNUCU_TAILSCALE_ADI
```
Tarayıcı:
- http://127.0.0.1:8081/admin/security

### Alternatif: Admin’i sadece tailnet IP’lerinden allowlist et
`deploy/.env`:
```env
ADMIN_ALLOW_IPS=100.64.0.0/10
```

> Bu yöntemde admin route’u yine public domain üzerinde durur ama sadece Tailnet IP’lerinden görülebilir.

---

## 4) Bonus: Cloudflare varsa bile Tailscale iyi bir “ikinci hat”
Cloudflare Access ile kimlik katmanı koysan bile, origin sunucuda Tailscale ile yönetim erişimini ayırmak çok güçlü bir pratik.
