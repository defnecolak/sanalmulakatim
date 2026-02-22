# Fail2ban (opsiyonel)

Bu proje zaten **uygulama içinde** temel bir “ban list” kullanır (WAF + otomatik geçici engel).

Fail2ban ise sunucu seviyesinde (Linux) **ek bir katman**dır: loglardan şüpheli davranışı yakalar ve IP’yi firewall üzerinden banlar.

> Not: Fail2ban’ı Docker içinde çalıştırmak mümkün ama iptables/nftables erişimi gerektirdiği için her ortamda sorunsuz değildir.
> Bu klasördeki dosyalar **host üzerinde** `/etc/fail2ban/` altına kopyalanacak şekilde hazırlanmıştır.

## 1) Caddy loglarının dosyaya yazıldığından emin olun

`deploy/Caddyfile` içinde loglar şu dosyaya yazılır:

- `/var/log/caddy/access.log` (JSON format)

Docker kullanıyorsan, `deploy/docker-compose.prod.yml` caddy servisine `./logs:/var/log/caddy` volume’u eklenmiştir.

## 2) Fail2ban kur

Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y fail2ban
```

## 3) Konfigleri kopyala

Bu repo içinden:

- `deploy/fail2ban/filter.d/sanal-mulakatim.conf` → `/etc/fail2ban/filter.d/`
- `deploy/fail2ban/jail.d/sanal-mulakatim.local` → `/etc/fail2ban/jail.d/`

Örnek:

```bash
sudo cp deploy/fail2ban/filter.d/sanal-mulakatim.conf /etc/fail2ban/filter.d/
sudo cp deploy/fail2ban/jail.d/sanal-mulakatim.local /etc/fail2ban/jail.d/
```

## 4) Servisi yeniden başlat

```bash
sudo systemctl restart fail2ban
sudo fail2ban-client status
sudo fail2ban-client status sanal-mulakatim
```

## 5) Ban list (kontrol / kaldırma)

```bash
sudo fail2ban-client get sanal-mulakatim banip
sudo fail2ban-client set sanal-mulakatim unbanip 1.2.3.4
```

## Tuning (agresiflik)

`jail.d/sanal-mulakatim.local` içindeki değerlerle oynayabilirsin:

- `maxretry` (kaç denemede ban)
- `findtime` (kaç saniyelik pencere)
- `bantime` (kaç saniye ban)

