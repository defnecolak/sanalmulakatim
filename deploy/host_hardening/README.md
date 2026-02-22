# Host Hardening (Ubuntu 22.04/24.04) — Sanal Mülakatım

Bu klasör **uygulama kodundan bağımsız** (VPS/host seviyesinde) sertleştirme adımlarını içerir.

Bu adımlar “hacklenmeyi imkânsız” yapmaz; ama:
- saldırı yüzeyini küçültür,
- brute-force/bot gürültüsünü azaltır,
- bir şey ters giderse toparlamayı hızlandırır.

> ⚠️ SSH ayarları risklidir: kendini kilitleyebilirsin.
> - Provider panelinden **console/recovery** erişimin olduğundan emin ol.
> - Ayar değiştirirken **mevcut SSH oturumunu kapatma**; ikinci bir terminalden yeni bağlantıyı test et.

---

## 1) Güvenlik duvarı (UFW)

Hedef: Gereksiz her şeyi kapat, sadece gerekli portları aç.

Önerilen minimum:
- 80/tcp, 443/tcp: web
- 22/tcp (veya custom): SSH (tercihen sadece kendi IP’nden)
- (opsiyonel) Tailscale kullanıyorsan: 41641/udp

Script: `ufw_setup.sh`

Kullanım (örnek):
```bash
cd deploy/host_hardening
sudo bash ufw_setup.sh \
  --ssh-port 22 \
  --ssh-allow-ip 1.2.3.4 \
  --enable-tailscale 1
```

> Not: IP’n değişkense (ev interneti), SSH’yi tek IP’ye kilitlemek can sıkabilir.
> Alternatif: SSH’yi Tailscale üzerinden kullan.

---

## 2) SSH sertleştirme

Amaç: Password login kapalı, root login kapalı, key-only.

Önerilen ayarlar:
- `PermitRootLogin no`
- `PasswordAuthentication no`
- `KbdInteractiveAuthentication no`
- `MaxAuthTries 3`
- `LoginGraceTime 30`

Örnek snippet: `sshd_config_hardening_snippet.conf`

Uygulama:
1) `/etc/ssh/sshd_config` içinde ilgili alanları ayarla
2) Test:
   ```bash
   sudo sshd -t
   ```
3) Reload:
   ```bash
   sudo systemctl reload ssh
   ```
4) Yeni terminalde yeni SSH bağlantısını dene.

---

## 3) Fail2ban (SSH için)

Hedef: SSH brute-force denemelerini otomatik ban’lemek.

Kurulum:
```bash
sudo apt update
sudo apt install -y fail2ban
```

Konfig:
- `fail2ban/jail.d/sshd.local`

Kopyalama:
```bash
sudo cp -v fail2ban/jail.d/sshd.local /etc/fail2ban/jail.d/sshd.local
sudo systemctl restart fail2ban
sudo fail2ban-client status sshd
```

---

## 4) Otomatik güvenlik güncellemeleri (unattended-upgrades)

Kurulum:
```bash
sudo apt update
sudo apt install -y unattended-upgrades
sudo dpkg-reconfigure --priority=low unattended-upgrades
```

Opsiyonel: `enable_unattended_upgrades.sh`

---

## 5) Log rotasyonu + disk dolmasına karşı önlem

- Docker json-file log driver zaten `max-size`/`max-file` ile sınırlı.
- Caddy access log: `deploy/logs/access.log` → logrotate önerilir.

Örnek: `logrotate_sanal_mulakatim.conf`

---

## 6) “En güvenlisi”: Admin paneli internete hiç açma

`deploy/Caddyfile` içinde `/admin/*` route’u zaten IP allowlist + BasicAuth altında ve allowlist dışı 404.

Ama en güvenlisi:
- Admin paneli **sadece localhost port** üzerinden açmak
- SSH tunnel ile erişmek

Bunun için `deploy/admin_local_port.md` dosyasına bak.
