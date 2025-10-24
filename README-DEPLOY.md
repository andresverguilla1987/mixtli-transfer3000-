# MixtliTransfer3000 Backend v2.1.1
Build: 2025-10-24T16:20:37.983853Z

- Auto-migraciones **dinámicas**: detecta si `users.id` es `uuid` o `bigint` y alinea `user_id` en `links`/`packages`. 
- Si la FK falla por incompatibilidad, se **omite** sin romper el deploy (queda sin FK, pero funcionando). 
- Packages, TTL, contadores y página `/dl/:id` con QR.

## ENV
DATABASE_URL=postgres://...
S3_ENDPOINT=https://8351c372...r2.cloudflarestorage.com
S3_BUCKET=mixtlitransfer3000
S3_ACCESS_KEY_ID=...
S3_SECRET_ACCESS_KEY=...
ALLOWED_ORIGINS=["https://<netlify>.netlify.app","http://localhost:8888"]
IP_SALT=algo-largo
PUBLIC_BASE_URL=https://<netlify>.netlify.app
FREE_MAX_UPLOAD_MB=3584
FREE_LINK_TTL_DEFAULT_DAYS=3
FREE_LINK_TTL_MAX_DAYS=30
UPLOAD_URL_TTL_SECONDS=3600
DOWNLOAD_URL_TTL_SECONDS_MAX=86400
