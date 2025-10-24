
-- MixtliTransfer3000 schema for plans FREE / PRO / PROMAX
-- Requires pgcrypto or uuid-ossp for gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TYPE plan_t AS ENUM ('FREE','PRO','PROMAX');

CREATE TABLE users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email text UNIQUE,
  phone text UNIQUE,
  password_hash text, -- optional if using OTP only
  plan plan_t NOT NULL DEFAULT 'FREE',
  plan_started_at timestamptz DEFAULT now(),
  plan_renews_every_days int NOT NULL DEFAULT 30,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

CREATE TABLE links (
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
CREATE INDEX links_user_idx ON links(user_id);
CREATE INDEX links_expires_idx ON links(expires_at);
CREATE INDEX links_active_idx ON links(active);

-- Rolling usage window (30d) materialized via sums at query-time
-- Optional table to cache monthly buckets
CREATE TABLE usage_buckets (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid REFERENCES users(id) ON DELETE CASCADE,
  window_start timestamptz NOT NULL,
  window_end timestamptz NOT NULL,
  total_bytes bigint NOT NULL DEFAULT 0,
  total_links int NOT NULL DEFAULT 0,
  UNIQUE(user_id, window_start, window_end)
);
