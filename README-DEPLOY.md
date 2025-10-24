# MixtliTransfer3000 Backend v2.1 — FULL POWER
**Build:** 2025-10-24T16:10:41.282653Z

Incluye:
- ESM puro + auto-migraciones
- **Packages** (link único para múltiples archivos) con `/api/package/*`
- Selector de TTL (el backend ya respeta `durationDays`)
- **Contador de descargas** (por paquete e ítem) vía `/api/dl/:pkg/:itemId`
- **Página de share** `/dl/:id` con **QR**

## ENV
```
DATABASE_URL=postgres://...
S3_ENDPOINT=https://8351c372...r2.cloudflarestorage.com
S3_BUCKET=mixtlitransfer3000
S3_ACCESS_KEY_ID=...
S3_SECRET_ACCESS_KEY=...
ALLOWED_ORIGINS=["https://<tu-netlify>.netlify.app","http://localhost:8888"]
IP_SALT=algo-largo
PUBLIC_BASE_URL=https://<tu-netlify>.netlify.app   # opcional para URLs absolutas en /dl/:id
FREE_MAX_UPLOAD_MB=3584
FREE_LINK_TTL_DEFAULT_DAYS=3
FREE_LINK_TTL_MAX_DAYS=30
UPLOAD_URL_TTL_SECONDS=3600
DOWNLOAD_URL_TTL_SECONDS_MAX=86400
```

## Rutas nuevas
- `POST /api/package/create` ⇒ `{ packageId, ttlDays }`
- `POST /api/package/presign` ⇒ `{ key, uploadUrl }`
- `GET  /api/package/meta/:id` ⇒ manifest
- `GET  /api/dl/:pkg/:itemId` ⇒ incrementa contador y redirige al S3 signed URL
- `GET  /dl/:id` ⇒ página para compartir + QR

> Nota: ZIP “todo en uno” no está en este build (implica streaming zip). Hoy tienes descargas individuales con conteo. Si lo quieres, lo integramos con `archiver` o compresión en worker.
