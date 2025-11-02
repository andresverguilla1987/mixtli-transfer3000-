# Mixtli — Ruta /api/upload (Proxy Upload)

**Objetivo:** Evitar CORS al subir a Cloudflare R2. El navegador envía los binarios al backend y el backend los sube con el SDK.

> Agrega lo siguiente a tu `server.js` (la versión que ya tienes en Render).

1) **Import** ya lo tienes:
```js
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3'
```

2) **Parser RAW** (colócalo ANTES del `app.use(express.json(...))` o usa sólo en la ruta):
```js
const rawUpload = express.raw({ type: '*/*', limit: '500mb' });
```

3) **Ruta** (colócala junto a tus rutas /api ):
```js
app.post('/api/upload', requireAuth, rawUpload, async (req, res) => {
  try {
    if (!s3) return res.status(500).json({ error: 's3_not_configured' })

    const filename = safeName(req.headers['x-file-name'] || `file-${Date.now()}`)
    const type = req.headers['content-type'] || 'application/octet-stream'
    const key  = `uploads/${new Date().toISOString().slice(0,10)}/${crypto.randomUUID()}-${filename}`

    const put = {
      Bucket: S3_BUCKET,
      Key: key,
      Body: req.body,
      ContentType: type
    }
    if (CONTENT_DISPOSITION) put.ContentDisposition = CONTENT_DISPOSITION

    await s3.send(new PutObjectCommand(put))
    res.json({ ok: true, key, publicUrl: await buildPublicUrl(key) })
  } catch (e) {
    console.error('[upload_failed]', e)
    res.status(500).json({ error: 'upload_failed', detail: String(e?.message || e) })
  }
})
```

Con esto, el front puede llamar `POST /api/upload` con:
- `Authorization: Bearer <token>`
- `Content-Type: <mimetype del archivo>`
- `x-file-name: <nombre original>`
- body = binario (`File`)

**No hay cambios en R2/CORS** requeridos.
