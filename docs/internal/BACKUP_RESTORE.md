# Backup / Restore

## Backup alma
```bash
./deploy/backup.sh
```
Çıktı: `deploy/backups/backup-YYYYmmdd-HHMMSS.tar.gz`

## Postgres backup/restore (DB_ENGINE=postgres)
Postgres kullanıyorsan SQLite yerine dump alman gerekir:

Backup:
```bash
./deploy/postgres/backup_pg.sh
```
Çıktı: `deploy/backups/backup-pg-YYYYmmdd-HHMMSS.sql.gz`

Restore:
```bash
./deploy/postgres/restore_pg.sh deploy/backups/backup-pg-....sql.gz
```

## Backup doğrulama (integrity)
```bash
./deploy/verify_backup.sh deploy/backups/backup-....tar.gz
```

## Restore
```bash
./deploy/restore.sh deploy/backups/backup-....tar.gz
```

## Retention
`BACKUP_RETENTION_DAYS` ile 30/60 gibi değer ver ve `backup_retention.sh` ile temizlet.

## Drill
Ayda 1:
- test sunucusuna restore
- smoke test koş
- süreyi not al
