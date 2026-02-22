-- 002: Core schema for Sanal Mülakatım (Postgres)

-- Usage counters
CREATE TABLE IF NOT EXISTS usage_daily(
  client_id TEXT NOT NULL,
  day TEXT NOT NULL,
  key TEXT NOT NULL,
  count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (client_id, day, key)
);

CREATE TABLE IF NOT EXISTS usage_total(
  client_id TEXT NOT NULL,
  key TEXT NOT NULL,
  count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (client_id, key)
);

-- Pro tokens
CREATE TABLE IF NOT EXISTS pro_tokens(
  token TEXT PRIMARY KEY,
  created_at BIGINT NOT NULL,
  provider TEXT,
  provider_ref TEXT,
  stripe_session_id TEXT,
  client_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_pro_tokens_client ON pro_tokens(client_id);
CREATE INDEX IF NOT EXISTS idx_pro_tokens_ref ON pro_tokens(provider, provider_ref);

-- Payment orders
CREATE TABLE IF NOT EXISTS payment_orders(
  order_id TEXT PRIMARY KEY,
  provider TEXT NOT NULL,
  client_id TEXT,
  email TEXT,
  created_at BIGINT NOT NULL,
  updated_at BIGINT,
  status TEXT,
  email_hash TEXT,
  provider_token TEXT,
  provider_payment_id TEXT,
  last_error TEXT,
  raw_response TEXT
);

CREATE INDEX IF NOT EXISTS idx_payment_orders_client ON payment_orders(client_id);
CREATE INDEX IF NOT EXISTS idx_payment_orders_status ON payment_orders(status);
CREATE INDEX IF NOT EXISTS idx_payment_orders_email_hash ON payment_orders(email_hash);

-- Email ↔ token mapping
CREATE TABLE IF NOT EXISTS email_token_links(
  email_hash TEXT NOT NULL,
  token TEXT NOT NULL,
  created_at BIGINT NOT NULL,
  PRIMARY KEY (email_hash, token)
);

CREATE INDEX IF NOT EXISTS idx_email_token_links_email ON email_token_links(email_hash);

-- One-time recovery links
CREATE TABLE IF NOT EXISTS recovery_links(
  token_hash TEXT PRIMARY KEY,
  email_hash TEXT NOT NULL,
  created_at BIGINT NOT NULL,
  expires_at BIGINT NOT NULL,
  consumed_at BIGINT
);

CREATE INDEX IF NOT EXISTS idx_recovery_links_email ON recovery_links(email_hash);

-- One-time privacy delete links
CREATE TABLE IF NOT EXISTS delete_links(
  token_hash TEXT PRIMARY KEY,
  email_hash TEXT NOT NULL,
  created_at BIGINT NOT NULL,
  expires_at BIGINT NOT NULL,
  consumed_at BIGINT
);

CREATE INDEX IF NOT EXISTS idx_delete_links_email ON delete_links(email_hash);

-- Ban list (hashed IP)
CREATE TABLE IF NOT EXISTS ip_bans(
  ban_key TEXT PRIMARY KEY,
  reason TEXT,
  created_at BIGINT NOT NULL,
  expires_at BIGINT NOT NULL
);

-- Security event stream
CREATE TABLE IF NOT EXISTS security_events(
  id BIGSERIAL PRIMARY KEY,
  ts BIGINT NOT NULL,
  event_type TEXT NOT NULL,
  ban_key TEXT,
  client_id TEXT,
  method TEXT,
  path TEXT,
  status INTEGER,
  weight INTEGER,
  ua TEXT,
  details TEXT
);

CREATE INDEX IF NOT EXISTS idx_security_events_ts ON security_events(ts);
CREATE INDEX IF NOT EXISTS idx_security_events_type ON security_events(event_type);
CREATE INDEX IF NOT EXISTS idx_security_events_bankey ON security_events(ban_key);
