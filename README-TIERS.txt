MixtliTransfer3000 — Presets de Tiers (GRAS / PRO / PRO MAX)

Cómo usar en Render (rápido):
1) Abre tu servicio → Environment.
2) Copia el contenido del preset deseado (.env.gras, .env.pro o .env.promax).
3) Pega y RELLENA S3_ACCESS_KEY_ID y S3_SECRET_ACCESS_KEY (solo esas dos).
4) Save → Restart.

Notas:
- No cambies S3_ENDPOINT ni S3_BUCKET (ya apuntan a tu R2/bucket).
- BACKEND_URL del frontend ya está sellado a: https://mixtli-transfer3000.onrender.com
- Netlify actual: https://lighthearted-froyo-9dd448.netlify.app
- Diferencias:
  * GRAS   → TTL 24h, 200 MB
  * PRO    → TTL 72h, 2 GB
  * PRO MAX→ TTL 168h (7d), 5 GB
- El backend actual es de "transfer puro": 1 archivo por presign, sin password.
  (Si luego quieres multi-archivo o password, lo agregamos en otra iteración.)

Tip de verificación:
  curl -s https://mixtli-transfer3000.onrender.com/api/health
  curl -s -X POST https://mixtli-transfer3000.onrender.com/api/presign -H "Content-Type: application/json" -d '{"filename":"demo.txt","contentType":"text/plain","contentLength":12}'
