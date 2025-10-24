# MixtliTransfer3000 — Backend (sellado)
Start (Render):
- Build: npm install --omit=dev --no-audit --no-fund
- Start: node server.js

Env obligatorias (Render → Environment):
- S3_ENDPOINT: endpoint de cuenta R2 (sin bucket)
- S3_BUCKET: mixtlitransfer
- S3_ACCESS_KEY_ID / S3_SECRET_ACCESS_KEY: tus tokens (pégalos en Render, no en archivos)
- ALLOWED_ORIGINS: ["https://lighthearted-froyo-9dd448.netlify.app","http://localhost:8888"]

Pruebas:
- GET /api/health -> { ok: true, bucket }
- POST /api/presign -> devuelve uploadUrl y downloadUrl
