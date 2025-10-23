Mixtli Transfer 3000 — Backend v2.4.1
===============================================

Contenido
---------
- server.js               → API (Express + AWS SDK v3)
- package.json            → dependencias
- .env.example            → ejemplo de variables de entorno
- README.md               → este archivo

Deploy en Render
----------------
1) Crea un nuevo servicio **Web** y apunta al repo/carpeta que contenga estos archivos.
2) **Environment** (copiar desde `.env.example` y completar credenciales R2).
3) Build Command:
   npm install --no-audit --no-fund
4) Start Command:
   node server.js
5) Probar:
   - GET /api/health
   - GET /api/debug-cred

Frontend
--------
fetch(putUrl, { method: 'PUT', headers: { 'Content-Type': file.type || 'application/octet-stream' }, body: file });
