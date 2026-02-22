# Cloudflare WAF / Ruleset Export-Import

Cloudflare kullanıyorsan WAF ve custom ruleset’leri export edip sürümleyebilirsin.

Scriptler: `deploy/cloudflare/`

## Export
```bash
export CF_API_TOKEN=...
export CF_ZONE_ID=...
python deploy/cloudflare/cf_export_rulesets.py --out deploy/cloudflare/export
```

## Import (dikkat)
Import destructive olabilir. Önce test zone üzerinde dene.
```bash
python deploy/cloudflare/cf_import_rulesets.py --in deploy/cloudflare/export
```

## Önerilen kurallar
- bot taraması path’leri block
- rate limit (billing, delete/recover)
- country allowlist (opsiyonel)
