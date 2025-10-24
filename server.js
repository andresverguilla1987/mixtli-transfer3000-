// MixtliTransfer3000 - Transfer Puro (Backend)
import 'dotenv/config'
import express from 'express'
import cors from 'cors'
import { randomUUID } from 'crypto'
import { S3Client, PutObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3'
import { getSignedUrl } from '@aws-sdk/s3-request-presigner'

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

if (!S3_ENDPOINT || !S3_BUCKET || !S3_ACCESS_KEY_ID || !S3_SECRET_ACCESS_KEY) {
  console.error('[FATAL] Missing S3/R2 env vars.')
  process.exit(1)
}

let allowedOrigins = []
try { allowedOrigins = JSON.parse(ALLOWED_ORIGINS) } catch (_e) { allowedOrigins = [] }
const linkTtlSeconds = Math.max(60, parseInt(LINK_TTL_HOURS, 10) * 3600)
const maxUploadBytes = Math.max(1, parseInt(MAX_UPLOAD_MB, 10)) * 1024 * 1024

const s3 = new S3Client({
  region: S3_REGION,
  endpoint: S3_ENDPOINT,
  credentials: { accessKeyId: S3_ACCESS_KEY_ID, secretAccessKey: S3_SECRET_ACCESS_KEY },
  forcePathStyle: String(S3_FORCE_PATH_STYLE).toLowerCase() === 'true',
})

const app = express()

app.use(cors({
  origin: function (origin, cb) {
    if (!origin) return cb(null, true)
    if (allowedOrigins.includes(origin)) return cb(null, true)
    cb(new Error('Origin not allowed: ' + origin))
  },
  methods: ['GET','POST','OPTIONS'],
  allowedHeaders: ['Content-Type', 'x-mixtli-token']
}))

app.use(express.json({ limit: '1mb' }))

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, service: 'mixtlitransfer3000', time: new Date().toISOString() })
})

app.post('/api/presign', async (req, res) => {
  try {
    const { filename, contentType, contentLength } = req.body || {}
    if (!filename || !contentType || !contentLength) return res.status(400).json({ error: 'filename, contentType, contentLength required' })
    if (Number(contentLength) > maxUploadBytes) return res.status(413).json({ error: 'File too large', maxBytes: maxUploadBytes })

    const ext = (filename.includes('.') ? filename.split('.').pop() : '').toLowerCase()
    const key = `mt/${new Date().toISOString().slice(0,10)}/${randomUUID()}${ext ? '.'+ext : ''}`

    const putCmd = new PutObjectCommand({ Bucket: S3_BUCKET, Key: key, ContentType: contentType, Metadata: { 'x-origin': 'mixtli-transfer3000' } })
    const uploadUrl = await getSignedUrl(s3, putCmd, { expiresIn: 3600 }) // 1h

    const getCmd = new GetObjectCommand({ Bucket: S3_BUCKET, Key: key, ResponseContentDisposition: `attachment; filename="${filename}"` })
    const downloadUrl = await getSignedUrl(s3, getCmd, { expiresIn: linkTtlSeconds })

    res.json({ key, uploadUrl, uploadHeaders: { 'Content-Type': contentType }, downloadUrl, expiresInSeconds: linkTtlSeconds })
  } catch (e) {
    console.error(e)
    res.status(500).json({ error: 'presign_failed', detail: String(e) })
  }
})

app.get('/', (_req, res) => res.send('MixtliTransfer3000 backend OK'))

app.listen(PORT, () => console.log('MixtliTransfer3000 listening on :' + PORT))
