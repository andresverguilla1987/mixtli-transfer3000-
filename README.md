# Mixtli Backend v2.14 (FINAL)

Node/Express + Postgres + Twilio + R2/S3 presign + paquetes y ZIP streaming.

## Deploy rápido (Render)
1. Crear **Web Service** en Render (Node 18+).
2. Variables de entorno (copiar `.env.example`):
   - `DATABASE_URL` (Postgres con SSL)
   - `JWT_SECRET`
   - `ALLOWED_ORIGINS` (JSON array con tu Netlify y localhost)
   - `S3_ENDPOINT`, `S3_BUCKET`, `S3_REGION=auto`,
     `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY`, `S3_FORCE_PATH_STYLE=true`
   - `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_FROM` (opcional para SMS)
   - `PUBLIC_BASE_URL` (opcional para links directos de archivos; no afecta `/share/:id`)
3. Build Command: `npm install --no-audit --no-fund`
4. Start Command: `node server.js`
5. Probar `GET /api/health`.

## Endpoints clave
- `POST /api/auth/register` (email o phone) → envía OTP
- `POST /api/auth/verify-otp` → token JWT
- `POST /api/presign` (JWT) → URL PUT a R2/S3
- `POST /api/complete` (JWT) → regresa publicUrl
- `POST /api/pack/create` (JWT) → crea paquete y entrega URL **relativa** `/share/:id`
- `GET  /share/:id` → HTML público simple
- `GET  /api/pack/:id/zip` → ZIP por streaming de archivos del paquete
- `GET  /api/health`

## Notas
- Para Netlify, usa `_redirects` en el **frontend**:
  ```
  /api/*   https://<tu-backend>.onrender.com/api/:splat   200
  /share/* https://<tu-backend>.onrender.com/share/:splat 200
  ```
- La página `/share/:id` siempre la sirve **el backend** (no el frontend), por eso se proxya.
