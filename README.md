Mixtli Transfer 3000 — Backend v2.4.2 (All-in-One)
=====================================================
- server.js (SDK v3 + selftest)
- package.json
- .env.example

Render:
- Build:  npm install --no-audit --no-fund
- Start:  node server.js

Pruebas:
- GET /api/health
- GET /api/debug-cred
- GET /api/selftest   ← diagnostica credenciales/permiso/escritura

Notas:
- R2 usa SigV4 y path-style (ya configurado).
- GET presign 24h máx recomendado.
