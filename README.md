# Mixtli Transfer MAX — Backend

**Node/Express + Postgres + Cloudflare R2**.

## Deploy (Render)
1. New Web Service → Node 18+.
2. Build command: `npm install --no-audit --no-fund`
3. Start command: `node --enable-source-maps server.js`
4. Add **Environment variables** using `.env.example` as template.
5. Make sure `ALLOWED_ORIGINS` includes your Netlify domain.
6. Open `/api/health` to verify.

## Important
- If you previously deployed an older schema, this version **auto-migrates** missing columns with `ALTER TABLE IF NOT EXISTS`.
- Regex crash fixed: phone sanitizer now uses `/[()\s-]/g` (hyphen at end).
