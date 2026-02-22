-- 001: schema_migrations table (idempotent)
CREATE TABLE IF NOT EXISTS schema_migrations(
  id TEXT PRIMARY KEY,
  applied_at BIGINT NOT NULL
);
