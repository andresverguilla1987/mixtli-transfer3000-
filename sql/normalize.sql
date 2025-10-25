-- sql/normalize.sql
DO $$
BEGIN
  IF to_regclass('public.links') IS NULL AND to_regclass('public.enlaces') IS NOT NULL THEN
    EXECUTE 'ALTER TABLE public.enlaces RENAME TO links';
  END IF;
END$$;

CREATE TABLE IF NOT EXISTS public.links ( id BIGSERIAL PRIMARY KEY );

ALTER TABLE public.links
  ADD COLUMN IF NOT EXISTS slug            TEXT,
  ADD COLUMN IF NOT EXISTS user_id         UUID,
  ADD COLUMN IF NOT EXISTS anon_ip         TEXT,
  ADD COLUMN IF NOT EXISTS plan            TEXT NOT NULL DEFAULT 'FREE',
  ADD COLUMN IF NOT EXISTS key             TEXT,
  ADD COLUMN IF NOT EXISTS filename        TEXT,
  ADD COLUMN IF NOT EXISTS content_type    TEXT NOT NULL DEFAULT 'application/octet-stream',
  ADD COLUMN IF NOT EXISTS size_bytes      BIGINT NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS expires_at      TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS active          BOOLEAN NOT NULL DEFAULT TRUE,
  ADD COLUMN IF NOT EXISTS password_hash   TEXT,
  ADD COLUMN IF NOT EXISTS password_salt   TEXT,
  ADD COLUMN IF NOT EXISTS password_hint   TEXT,
  ADD COLUMN IF NOT EXISTS brand_json      JSONB,
  ADD COLUMN IF NOT EXISTS max_downloads   INT,
  ADD COLUMN IF NOT EXISTS downloads       INT NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS created_at      TIMESTAMPTZ NOT NULL DEFAULT now();

CREATE UNIQUE INDEX IF NOT EXISTS idx_links_key_unique ON public.links(key);
CREATE UNIQUE INDEX IF NOT EXISTS idx_links_slug_unique ON public.links(slug);
CREATE INDEX IF NOT EXISTS idx_links_user_created ON public.links(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_links_anon_created ON public.links(anon_ip, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_links_expires ON public.links(expires_at);
