
CREATE EXTENSION IF NOT EXISTS pgcrypto;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'plan_t') THEN
    CREATE TYPE plan_t AS ENUM ('FREE','PRO','PROMAX');
  END IF;
END$$;

CREATE TABLE IF NOT EXISTS users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email text UNIQUE,
  phone text UNIQUE,
  password_hash text,
  plan plan_t NOT NULL DEFAULT 'FREE',
  plan_started_at timestamptz DEFAULT now(),
  plan_renews_every_days int NOT NULL DEFAULT 30,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS links (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  plan plan_t NOT NULL,
  key text NOT NULL,
  filename text,
  content_type text,
  size_bytes bigint NOT NULL,
  expires_at timestamptz NOT NULL,
  created_at timestamptz DEFAULT now(),
  active boolean DEFAULT true
);

CREATE INDEX IF NOT EXISTS links_user_idx ON links(user_id);
CREATE INDEX IF NOT EXISTS links_expires_idx ON links(expires_at);
CREATE INDEX IF NOT EXISTS links_active_idx ON links(active);
