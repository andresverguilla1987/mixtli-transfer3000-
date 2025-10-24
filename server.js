// MixtliTransfer3000 — Transfer Puro (Backend estable)
// Stack: Node 18+, Express, AWS SDK v3 (S3-compatible: Cloudflare R2)

// ───────────────────────────────────────────────────────────────────────────────
// Dependencias
import 'dotenv/config'
import express from 'express'
import cors from 'cors'
import { randomUUID } from 'crypto'
import { S3Client, PutObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3'
import { getSignedUrl } from '@aws-sdk/s3-request-presigner'

// ───────────────────────────────────────────────────────────────────────────────
// Env vars (no pongas el bucket dentro del ENDPOINT)
const {
  PORT = 10000,
  S3_ENDPOINT,
  S3_REGION = 'auto',
  S3_BUCKET,
  S3_ACCESS_KEY_ID,
  S3_SECRET_ACCESS_KEY,
  ALLOWED_ORIGINS = '[]',
  LINK_TTL_HOURS = '72',
  MAX_UPLOAD_MB = '200',
  S3_FORCE_PATH_STYLE = 'true'
} = process.env

// Validaciones tempranas
function fail(msg) {
  console.error('[FATAL]', msg)
  process.exit(1)
}
if (!S3_ENDPOINT) fail('S3_ENDPOINT requerido (solo endpoint de cuenta, SIN bucket).')
if (!S3_BUCKET) fail('S3_BUCKET requerido.')
if (!S3_ACCESS_KEY_ID || !S3_SECRET_ACCESS_KEY) fail('S3_ACCESS_KEY_ID/SECRET requeridos.')

let allowedOrigins = []
try { allowedOrigins = JSON.parse(ALLOWED_ORIGINS || '[]') } catch { allowedOrigins = [] }

const ttlHours = Number.parseInt(String(LINK_TTL_HOURS), 10)
const linkTtlSeconds = Number.isFinite(ttlHours) && ttlHours > 0 ? ttlHours * 3600 : 72 * 3600

const maxMB = Number.parseInt(String(MAX_UPLOAD_MB), 10)
const maxUploadBytes = Number.isFinite(maxMB) && maxMB > 0 ? maxMB * 1024 * 1024 : 200 * 1024 * 1024

// Cliente S3/R2 (path-style para R2)
const s3 = new S3Client({
  region: S3_REGION,
  endpoint: S3_ENDPOINT.replace(/\/+$/, ''), // sin trailing slash
  credentials: { accessKeyId: S3_ACCESS_KEY_ID, secretAccessKey: S3_SECRET_ACCESS_KEY },
  forcePathStyle: String(S3_FORCE_PATH_STYLE).toLowerCase() === 'true'
})

// ───────────────────────────────────────────────────────────────────────────────
// App
const app = express()

// CORS estricto (pero permite Postman/curl: origin null)
app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true)
    if (allowedOrigins.includes(origin)) return cb(null, true)
    cb(new Error('Origin not allowed: ' + origin))
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type'],
  credentials: false
}))

// Preflight explícito (evita 404 en OPTIONS)
app.options('*', cors())

app.use(express.json({ limit: '1mb' }))

// ───────────────────────────────────────────────────────────────────────────────
// Health
app.get('/api/health', (_req, res) => {
  res.json({
    ok: true,
    service: 'mixtlitransfer3000',
    time: new Date().toISOString(),
    bucket: S3_BUCKET
  })
})

// Presign: regresa PUT (upload) y GET (download) firmados
app.post('/api/presign', async (req, res) => {
  try {
    const { filename, contentType, contentLength } = req.body || {}

    if (!filename || typeof filename !== 'string') {
      return res.status(400).json({ error: 'filename requerido' })
    }
    if (!contentType || typeof contentType !== 'string') {
      return res.status(400).json({ error: 'contentType requerido' })
    }
    const size = Number(contentLength)
    if (!Number.isFinite(size) || size <= 0) {
      return res.status(400).json({ error: 'contentLength inválido' })
    }
    if (size > maxUploadBytes) {
      return res.status(413).json({ error: 'File too large', maxBytes: maxUploadBytes })
    }

    const ext = (filename.includes('.') ? filename.split('.').pop() : '').toLowerCase()
    const key = `mt/${new Date().toISOString().slice(0, 10)}/${randomUUID()}${ext ? '.' + ext : ''}`

    // Presign PUT (1 hora para subir)
    const putCmd = new PutObjectCommand({
      Bucket: S3_BUCKET,
      Key: key,
      ContentType: contentType,
      Metadata: { 'x-origin': 'mixtlitransfer3000' }
    })
    const uploadUrl = await getSignedUrl(s3, putCmd, { expiresIn: 3600 })

    // Presign GET (descarga con expiración configurable)
    const getCmd = new GetObjectCommand({
      Bucket: S3_BUCKET,
      Key: key,
      ResponseContentDisposition: `attachment; filename="${filename}"`
    })
    const downloadUrl = await getSignedUrl(s3, getCmd, { expiresIn: linkTtlSeconds })

    return res.json({
      key,
      uploadUrl,
      uploadHeaders: { 'Content-Type': contentType },
      downloadUrl,
      expiresInSeconds: linkTtlSeconds
    })
  } catch (err) {
    console.error('presign_failed:', err)
    res.status(500).json({ error: 'presign_failed' })
  }
})

// Raíz
app.get('/', (_req, res) => {
  res.send('MixtliTransfer3000 backend OK. Usa /api/health y /api/presign.')
})

// ───────────────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`MixtliTransfer3000 listening on :${PORT}`)
})
