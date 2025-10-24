-- MixtliTransfer3000 minimal schema
CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  email TEXT UNIQUE,
  phone TEXT UNIQUE,
  plan  TEXT NOT NULL DEFAULT 'FREE',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS links (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
  anon_ip TEXT,
  plan TEXT NOT NULL,
  key  TEXT NOT NULL,
  filename TEXT NOT NULL,
  content_type TEXT NOT NULL,
  size_bytes BIGINT NOT NULL DEFAULT 0,
  expires_at TIMESTAMPTZ NOT NULL,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_links_key_unique ON links(key);
CREATE INDEX IF NOT EXISTS idx_links_user_created ON links(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_links_anon_created ON links(anon_ip, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_links_expires ON links(expires_at);
