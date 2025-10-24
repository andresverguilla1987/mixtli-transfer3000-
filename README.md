
# MixtliTransfer3000 Backend Bundle
Express + Postgres + R2 (Cloudflare) — Planes: FREE / PRO / PROMAX

## Endpoints
- `POST /api/auth/register`  { email } | { phone }  → OTP (en logs)
- `POST /api/auth/verify-otp` { email/phone, otp } → { token, user }
- `GET /api/me` (Bearer JWT)
- `POST /api/presign` (Bearer JWT)  → { uploadUrl, downloadUrl, expiresInSeconds }

## Env (Render)
- `DATABASE_URL` (usa la interna de Render)
- `JWT_SECRET` (tu secreto)
- R2: `S3_ENDPOINT,S3_BUCKET,S3_ACCESS_KEY_ID,S3_SECRET_ACCESS_KEY,S3_REGION=auto,S3_FORCE_PATH_STYLE=true`
- `ALLOWED_ORIGINS=["https://TU-NETLIFY.netlify.app","http://localhost:8888"]`

### Planes
- FREE: 3.5GB por link, 3 o 30 días, máx 10 links / 30d
- PRO: 400GB / 30d, links ilimitados hasta agotar GB, vida 7d
- PROMAX: premium, vida 22d

## DB
Crea tablas:
```bash
psql "$DATABASE_URL" -f schema.sql
```

## Run
```bash
npm i
npm start
```
