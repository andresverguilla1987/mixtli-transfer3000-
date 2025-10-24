# MixtliTransfer3000 Backend FIX

**Fecha:** 2025-10-24T15:55:47.377836Z

Este paquete arregla:
- Error `require is not defined` (ESM puro)
- Falta de tablas `users` y `links` (auto-migraciones al arrancar)
- Respuesta 404 en `/` (agrega un ping básico)

## Deploy rápido en Render

1. Crea un nuevo servicio Web (Node).
2. Sube este proyecto a un repo o copia los archivos.
3. **Build:** `npm install --no-audit --no-fund`
4. **Start:** `node --enable-source-maps server.js`
5. **Node:** 20.x

### Env vars (Render)
- `DATABASE_URL` (Postgres)
- `S3_ENDPOINT` = https://8351c372...
- `S3_BUCKET` = mixtlitransfer3000
- `S3_ACCESS_KEY_ID` = (R2 token)
- `S3_SECRET_ACCESS_KEY` = (R2 secret)
- `ALLOWED_ORIGINS` = ["https://lighthearted-froyo-9dd448.netlify.app","http://localhost:8888"]
- `IP_SALT` = algo-largo-aleatorio (recomendado)
- (Opcionales) límites FREE/PRO

## Endpoints
- `GET /` -> `{ "ok": true }`
- `GET /api/health`
- `POST /api/presign`

## Migraciones
Además de las auto-migraciones, tienes el SQL en `migrations/001_init.sql` por si quieres aplicarlo manualmente en psql.
