# Cloudflare WAF / Ruleset Export-Import

Amaç: Cloudflare zone ayarlarını (Rulesets/WAF) **yedeklemek** ve gerekirse geri yüklemek.

## Gerekenler
- Cloudflare API Token (en azından Rulesets read/write)
- Zone ID

Env:
```bash
export CF_API_TOKEN="..."
export CF_ZONE_ID="..."
```

## Export
```bash
python cf_export_rulesets.py --out export
```

Bu, `export/rulesets_index.json` ve her ruleset için `ruleset_<id>.json` üretir.

## Import (DİKKAT)
Bu işlem mevcut ruleset’leri **üzerine yazabilir**.
Önce test zone’da dene.

```bash
python cf_import_rulesets.py --in export --dry-run
python cf_import_rulesets.py --in export
```

## Güvenlik Notu
API token’ı repo’ya koyma. `.env` veya secret manager kullan.
