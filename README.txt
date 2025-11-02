# Mixtli Backend v2.14.6-lock+wt+migrate

## Deploy en Render
1) Crea un **Web Service** Node 18+.
2) Comando Build: `npm install --no-audit --no-fund`
3) Start: `node --enable-source-maps server.js`
4) Añade las variables de entorno (usa `.env.example` como guía).
5) Asegúrate de poner `ALLOWED_ORIGINS` como **array JSON** válido.
6) `BACKEND_PUBLIC_ORIGIN` debe apuntar a tu URL pública de Render (https://xxx.onrender.com).

- Este server hace **auto-migración** de columnas nuevas al arrancar (`migrateDb()`), así no revienta `/api/pack/create` cuando faltan `password_hash` & co.
- ZIP por streaming: primero intenta `GetObject` de S3/R2 y cae a `fetch()` si es público.
- Protección con contraseña (header `x-package-password`), TTL, límites de descargas y rate limit por IP.

## Frontend (Netlify)
Crea `_redirects` en tu frontend con (reemplaza BACKEND_URL):
```
/api/*  https://<BACKEND_URL>/api/:splat  200
/share/*  https://<BACKEND_URL>/share/:splat  200
```
Súbelo en la raíz del **build** del front.

## Smoke
- `GET /api/health`
- `POST /api/auth/register` {email|phone}
- `POST /api/auth/verify-otp` -> recibe {token}
- `POST /api/presign` (Bearer token) -> PUT al URL firmado -> `POST /api/complete`
- `POST /api/pack/create` con files[] -> devuelve {url:'/share/:id'}
- `GET /api/pack/:id/zip` (si hay password, envía header `x-package-password`)
