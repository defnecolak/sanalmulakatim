# Incident Playbook

## 0) Hedef
- Servisi ayakta tut
- Maliyeti kontrol et
- Kanıt topla (diagnostics bundle)
- Root cause + kalıcı çözüm

## 1) İlk 5 dakika (Triage)
- [ ] `/api/healthz` up mı?
- [ ] 5xx spike var mı?
- [ ] Lockdown aktif mi?
- [ ] Caddy erişim loglarında anomali var mı?
- [ ] App log’da exception pattern’i var mı?

## 2) Kanıt topla
Sunucuda:
```bash
./deploy/runbook/collect_diagnostics.sh
```
Çıktı: `deploy/backups/diag-*.tar.gz`

## 3) En sık senaryolar
### A) Bot saldırısı / tarama
Belirti: 403/429/WAF/ban spike.
- Lockdown’ı kısa süreli aç
- CAPTCHA zorunlu
- Cloudflare rate limit / bot fight mode
- Admin panel erişimi sadece allowlist

### B) OpenAI/LLM rate limit / timeout
Belirti: evaluate/transcribe hataları.
- evaluate endpoint limitlerini düşür
- backoff/retry
- degrade mode: sadece soru üret, feedback’i kapat (kısa süre)

### C) Ödeme callback sorunları
Belirti: ödeme var ama token yok.
- Callback ulaşmış mı?
- provider verify endpoint hatası var mı?
- Idempotency kayıtları tutarlı mı?

### D) Disk doldu / log şişmesi
- log rotate
- backup retention
- docker log driver max-size kontrol

## 4) Postmortem
- Zaman çizelgesi
- Kök neden
- Aksiyonlar (owner + due date)
