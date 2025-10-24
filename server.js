// MixtliTransfer3000 - Transfer Puro (Backend)
// Node/Express + AWS SDK v3 (S3-compatible) for Cloudflare R2
// Endpoints:
//   GET  /api/health
//   POST /api/presign  { filename, contentType, contentLength }
// Returns: { key, uploadUrl, uploadHeaders, downloadUrl }
//
// Notes:
// - No DB. Download URL is a presigned GET with expiry (LINK_TTL_HOURS).
// - CORS locked to ALLOWED_ORIGINS (JSON array).
// - Force path-style for R2 (S3_FORCE_PATH_STYLE=true).
// - MAX_UPLOAD_MB protects server-side policy only; PUT goes direct to R2.
//
// Deploy tips (Render):
//  Build:   npm install --omit=dev --no-audit --no-fund
//  Start:   node server.js
//
// Env vars required (see .env.example).

import 'dotenv/config'
import express from 'express'
import cors from 'cors'
import { randomUUID } from 'crypto'
import { S3Client, PutObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3'
import { getSignedUrl } from '@aws-sdk/s3-request-presigner'

// ----- Env & defaults -----
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
  console.error('[FATAL] Missing S3/R2 env vars. See .env.example')
  process.exit(1)
}

let allowedOrigins = []
try { allowedOrigins = JSON.parse(ALLOWED_ORIGINS) } catch (_e) { allowedOrigins = [] }
const linkTtlSeconds = Math.max(60, parseInt(LINK_TTL_HOURS, 10) * 3600)
const maxUploadBytes = Math.max(1, parseInt(MAX_UPLOAD_MB, 10)) * 1024 * 1024

// ----- S3 client (R2 compatible) -----
const s3 = new S3Client({
  region: S3_REGION,
  endpoint: S3_ENDPOINT,
  credentials: {
    accessKeyId: S3_ACCESS_KEY_ID,
    secretAccessKey: S3_SECRET_ACCESS_KEY,
  },
  forcePathStyle: String(S3_FORCE_PATH_STYLE).toLowerCase() === 'true',
})

// ----- App -----
const app = express()

// CORS strict
app.use(cors({
  origin: function (origin, cb) {
    if (!origin) return cb(null, true) // Allow curl/Postman
    if (allowedOrigins.includes(origin)) return cb(null, true)
    cb(new Error('Origin not allowed by CORS: ' + origin))
  },
  methods: ['GET','POST','OPTIONS'],
  allowedHeaders: ['Content-Type', 'x-mixtli-token'],
  credentials: false
}))

app.use(express.json({ limit: '1mb' }))

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, service: 'mixtlitransfer3000', time: new Date().toISOString() })
})

app.post('/api/presign', async (req, res) => {
  try {
    const { filename, contentType, contentLength } = req.body || {}
    if (!filename || !contentType || !contentLength) {
      return res.status(400).json({ error: 'filename, contentType, contentLength required' })
    }
    if (Number(contentLength) > maxUploadBytes) {
      return res.status(413).json({ error: 'File too large', maxBytes: maxUploadBytes })
    }

    const ext = (filename.includes('.') ? filename.split('.').pop() : '').toLowerCase()
    const key = `mt/${new Date().toISOString().slice(0,10)}/${randomUUID()}${ext ? '.'+ext : ''}`

    // Presign PUT
    const putCmd = new PutObjectCommand({
      Bucket: S3_BUCKET,
      Key: key,
      ContentType: contentType,
      // Optional: server-side metadata for minimal tracing
      Metadata: { 'x-origin': 'mixtli-transfer3000' }
    })
    const uploadUrl = await getSignedUrl(s3, putCmd, { expiresIn: 3600 }) // 1h to upload

    // Presign GET (download link)
    const getCmd = new GetObjectCommand({ Bucket: S3_BUCKET, Key: key, ResponseContentDisposition: `attachment; filename="${filename}"` })
    const downloadUrl = await getSignedUrl(s3, getCmd, { expiresIn: linkTtlSeconds })

    return res.json({
      key,
      uploadUrl,
      uploadHeaders: { 'Content-Type': contentType },
      downloadUrl,
      expiresInSeconds: linkTtlSeconds
    })
  } catch (err) {
    console.error('presign error', err)
    res.status(500).json({ error: 'presign_failed', detail: String(err) })
  }
})

// Root hint
app.get('/', (_req, res) => res.send('MixtliTransfer3000 backend OK. Use /api/health and /api/presign.'))

app.listen(PORT, () => {
  console.log(`MixtliTransfer3000 listening on :${PORT}`)
})
