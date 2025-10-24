# MixtliTransfer3000 — Backend (Transfer Puro)
Endpoints:
- GET /api/health
- POST /api/presign { filename, contentType, contentLength } -> { uploadUrl, downloadUrl }
Deploy:
- Build: npm install --omit=dev --no-audit --no-fund
- Start: node server.js
Set env vars as in .env.example
