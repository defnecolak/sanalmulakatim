# systemd Timers

Bu dosyalar **örnek** unit/timer’lardır.
Kurulumdan önce yolları kendi sunucu path’ine göre düzenle:

Örnek proje yolu:
- `/opt/sanal-mulakatim/interview-sim-lite-launch`

## Kurulum
```bash
sudo cp deploy/systemd/*.service /etc/systemd/system/
sudo cp deploy/systemd/*.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sanal-mulakatim-backup.timer
sudo systemctl enable --now sanal-mulakatim-verify-backup.timer
```

Durum:
```bash
systemctl list-timers | grep sanal-mulakatim
journalctl -u sanal-mulakatim-backup.service -n 100 --no-pager
```
