// Mixtli Transfer – Backend v2.11.2 (SMS-only + presign S3/R2)
// OTP por SMS (Twilio) + CORS + RateLimit + Purga OTP + Debug + Presign
// Requiere Node 18+ (fetch nativo). Si no, activa fallback.

import 'dotenv/config'
import express from 'express'
import cors from 'cors'
import jwt from 'jsonwebtoken'
import pg from 'pg'
import nodemailer from 'nodemailer'
import twilio from 'twilio'
import rateLimit from 'express-rate-limit'

// --- Presign S3/R2
import crypto from 'crypto'
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3'
import { getSignedUrl } from '@aws-sdk/s3-request-presigner'

// --- Fallback de fetch para runtimes viejos ---
if (!globalThis.fetch) {
  const { default: nodeFetch } = await import('node-fetch')
  globalThis.fetch = nodeFetch
}

const {
  PORT = 10000,
  DATABASE_URL,
  JWT_SECRET = 'change_me',
  OTP_TTL_MIN = '10',

  // Email (opcional)
  SENDGRID_API_KEY,
  SENDGRID_FROM,
  SMTP_HOST,
  SMTP_PORT = '587',
  SMTP_USER,
  SMTP_PASS,
  SMTP_FROM,

  // CORS
  ALLOWED_ORIGINS = '["http://localhost:8888","http://localhost:5173","http://127.0.0.1:5173","http://localhost:3000","https://lighthearted-froyo-9dd448.netlify.app"]',

  // Twilio (solo SMS)
  TWILIO_ACCOUNT_SID,
  TWILIO_AUTH_TOKEN,
  TWILIO_FROM, // p. ej. +16209517456

  // S3/R2
  S3_ENDPOINT,
  S3_BUCKET,
  S3_REGION = 'auto',
  S3_ACCESS_KEY_ID,
  S3_SECRET_ACCESS_KEY,
  S3_FORCE_PATH_STYLE = 'true',
  PUBLIC_BASE_URL // opcional para URLs bonitas
} = process.env

if (!DATABASE_URL) {
  console.error('[FATAL] Missing DATABASE_URL')
  process.exit(1)
}

// ---------- DB ----------
const pool = new pg.Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
})

async function initDb() {
  try { await pool.query('CREATE EXTENSION IF NOT EXISTS "pgcrypto";') }
  catch (e) { console.warn('[DB] pgcrypto no disponible:', e?.message || e) }

  try { await pool.query('CREATE EXTENSION IF NOT EXISTS "uuid-ossp";') }
  catch (e) { console.warn('[DB] uuid-ossp no disponible:', e?.message || e) }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      email TEXT,
      phone TEXT,
      plan TEXT NOT NULL DEFAULT 'FREE',
      plan_expires_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `)

  await pool.query(`
    CREATE TABLE IF NOT EXISTS otps (
      id BIGSERIAL PRIMARY KEY,
      key TEXT NOT NULL,
      code TEXT NOT NULL,
      exp TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `)

  // índices únicos condicionales
  await pool.query(`
  DO $$
  BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname='users_email_key') THEN
      EXECUTE 'CREATE UNIQUE INDEX users_email_key ON users(email) WHERE email IS NOT NULL';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname='users_phone_key') THEN
      EXECUTE 'CREATE UNIQUE INDEX users_phone_key ON users(phone) WHERE phone IS NOT NULL';
    END IF;
  END $$;`)

  console.log('[DB] ready')
}

// ---------- OTP helpers ----------
function rand6() { return String(Math.floor(100000 + Math.random() * 900000)) }

async function createOtp(key, ttlMin) {
  const code = rand6()
  await pool.query(
    `INSERT INTO otps (key, code, exp)
     VALUES ($1, $2, now() + ($3 || ' minutes')::interval)`,
    [key, code, ttlMin]
  )
  return code
}

async function verifyOtpDb(key, code) {
  const q = await pool.query(
    `SELECT id, code, exp FROM otps WHERE key=$1 ORDER BY id DESC LIMIT 1`,
    [key]
  )
  if (!q.rows.length) return false
  const row = q.rows[0]
  if (row.code !== String(code)) return false
  if (new Date(row.exp) < new Date()) return false
  await pool.query(`DELETE FROM otps WHERE id=$1`, [row.id])
  return true
}

function signToken(user) {
  return jwt.sign({ uid: user.id, plan: user.plan }, JWT_SECRET, { expiresIn: '30d' })
}

async function purgeOtps() {
  try { await pool.query('DELETE FROM otps WHERE exp < now()') }
  catch (e) { console.warn('[OTP purge] error:', e?.message || e) }
}
setInterval(purgeOtps, 10 * 60 * 1000)

// ---------- Mail (opcional) ----------
let smtpTransport = null
if (SMTP_HOST && SMTP_USER && SMTP_PASS) {
  const portN = parseInt(SMTP_PORT || '587', 10)
  smtpTransport = nodemailer.createTransport({
    host: SMTP_HOST,
    port: portN,
    secure: portN === 465,
    auth: { user: SMTP_USER, pass: SMTP_PASS },
  })
}

async function sendMail(to, subject, text) {
  try {
    if (SENDGRID_API_KEY && SENDGRID_FROM) {
      const body = {
        personalizations: [{ to: [{ email: to }] }],
        from: { email: SENDGRID_FROM },
        subject,
        content: [{ type: 'text/plain', value: text }],
      }
      const r = await fetch('https://api.sendgrid.com/v3/mail/send', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${SENDGRID_API_KEY}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
      })
      if (!r.ok) console.warn('[MAIL] SendGrid error:', await r.text())
      return
    }
    if (smtpTransport) {
      await smtpTransport.sendMail({ from: SMTP_FROM || SMTP_USER, to, subject, text })
      return
    }
    console.log('[MAIL:demo]', to, subject, text)
  } catch (e) {
    console.warn('[MAIL] failed', e?.message || e)
  }
}

// ---------- Twilio SMS-only ----------
let twilioClient = null
if (TWILIO_ACCOUNT_SID && TWILIO_AUTH_TOKEN) {
  twilioClient = twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
}

function normalizePhone(p) {
  if (!p) return ''
  let s = String(p).replace(/[\s\-\(\)]/g, '')
  if (s.toLowerCase().startsWith('whatsapp:')) s = s.slice('whatsapp:'.length)
  if (!s.startsWith('+') && /^\d{10,15}$/.test(s)) s = '+' + s
  return s
}

async function sendSmsOnly(rawTo, text) {
  const to = normalizePhone(rawTo)
  if (!twilioClient) { console.log('[SMS:demo]', to, text); return }
  if (!TWILIO_FROM) { console.warn('[SMS] Falta TWILIO_FROM'); return }
  try {
    console.log('[SMS ONLY] to=', to, 'from=', TWILIO_FROM)
    const msg = await twilioClient.messages.create({ to, from: TWILIO_FROM, body: text })
    console.log('[Twilio SID]', msg.sid, 'status=', msg.status)
  } catch (e) {
    console.warn('[SMS ERROR]', e?.code || e?.status || '', e?.message || String(e))
  }
}

// ---------- S3/R2 Presign ----------
let s3 = null
const FORCE_PATH = String(S3_FORCE_PATH_STYLE).toLowerCase() === 'true'

if (S3_ENDPOINT && S3_BUCKET && S3_ACCESS_KEY_ID && S3_SECRET_ACCESS_KEY) {
  s3 = new S3Client({
    region: S3_REGION,
    endpoint: S3_ENDPOINT,
    credentials: { accessKeyId: S3_ACCESS_KEY_ID, secretAccessKey: S3_SECRET_ACCESS_KEY },
    forcePathStyle: FORCE_PATH,
  })
}

function safeName(name = '') {
  return name.replace(/[^\w\-.]+/g, '_').slice(0, 180)
}

function requireAuth(req, res, next) {
  const auth = req.headers.authorization || ''
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : ''
  if (!token) return res.status(401).json({ error: 'no_token' })
  try { jwt.verify(token, JWT_SECRET); next() }
  catch { res.status(401).json({ error: 'invalid_token' }) }
}

async function buildPublicUrl(key) {
  if (PUBLIC_BASE_URL) return `${PUBLIC_BASE_URL.replace(/\/+$/,'')}/${key}`
  const host = S3_ENDPOINT.replace(/^https?:\/\//, '')
  return FORCE_PATH
    ? `${S3_ENDPOINT}/${S3_BUCKET}/${key}`
    : `https://${S3_BUCKET}.${host}/${key}`
}

// ---------- App / CORS ----------
const app = express()

let ORIGINS = []
try { ORIGINS = JSON.parse(ALLOWED_ORIGINS) } catch { ORIGINS = [] }

function isNetlifyPreview(origin) {
  try { return /\.netlify\.app$/i.test(new URL(origin).hostname) } catch { return false }
}

const corsMw = cors({
  origin: (o, cb) => {
    if (!o) return cb(null, true)
    if (ORIGINS.includes(o) || isNetlifyPreview(o)) return cb(null, true)
    return cb(new Error('origin_not_allowed'))
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-admin-token', 'x-cron-token', 'x-mixtli-token'],
  optionsSuccessStatus: 204,
})

app.use((req, res, next) => corsMw(req, res, (err) => {
  if (err?.message === 'origin_not_allowed') {
    return res.status(403).json({ error: 'origin_not_allowed', origin: req.headers.origin || null })
  }
  next()
}))
app.options('*', corsMw)

app.set('trust proxy', 1)
app.use(express.json({ limit: '2mb' }))

// ---------- Rate-limit OTP ----------
const otpLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 8,
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => req.method === 'OPTIONS',
})

// ---------- Rutas ----------
app.get('/', (_req, res) => res.type('text/plain').send('OK'))
app.get('/api/health', (_req, res) =>
  res.json({ ok: true, time: new Date().toISOString(), ver: '2.11.2', channel: 'sms-only' }))

// Enviar OTP
app.post('/api/auth/register', otpLimiter, async (req, res) => {
  try {
    let { email, phone } = req.body || {}
    email = email ? String(email).trim().toLowerCase() : ''
    phone = phone ? String(phone).trim() : ''
    const id = email || phone
    if (!id) return res.status(400).json({ error: 'email_or_phone_required' })

    const code = await createOtp(id, OTP_TTL_MIN)
    if (email) {
      await sendMail(email, 'Tu código Mixtli', `Tu código es: ${code}\nExpira en ${OTP_TTL_MIN} minutos.`)
    } else {
      await sendSmsOnly(phone, `Mixtli: tu código es ${code}. Expira en ${OTP_TTL_MIN} min.`)
    }
    res.json({ ok: true, msg: 'otp_sent' })
  } catch (e) {
    console.error(e)
    res.status(500).json({ error: 'otp_send_failed' })
  }
})

// Alias legacy
app.post('/api/auth/verify', (req, _res, next) => { req.url = '/api/auth/verify-otp'; next() })

// Verificar OTP
app.post('/api/auth/verify-otp', async (req, res) => {
  try {
    let { email, phone, otp } = req.body || {}
    email = email ? String(email).trim().toLowerCase() : ''
    phone = phone ? String(phone).trim() : ''
    const id = email || phone
    if (!id || !otp) return res.status(400).json({ error: 'need_id_and_otp' })

    const ok = await verifyOtpDb(id, otp)
    if (!ok) return res.status(400).json({ error: 'otp_invalid' })

    let row
    if (email) {
      row = (await pool.query(
        `INSERT INTO users (email, plan)
         VALUES ($1,'FREE')
         ON CONFLICT (email) DO UPDATE SET updated_at=now()
         RETURNING id,email,phone,plan,plan_expires_at`,
        [email]
      )).rows[0]
    } else {
      row = (await pool.query(
        `INSERT INTO users (phone, plan)
         VALUES ($1,'FREE')
         ON CONFLICT (phone) DO UPDATE SET updated_at=now()
         RETURNING id,email,phone,plan,plan_expires_at`,
        [phone]
      )).rows[0]
    }

    const token = signToken(row)
    res.json({ token, user: row })
  } catch (e) {
    console.error(e)
    res.status(500).json({ error: 'verify_failed' })
  }
})

// --- Presign S3/R2 (subidas tipo WeTransfer) ---
app.post('/api/presign', requireAuth, async (req, res) => {
  try {
    if (!s3) return res.status(500).json({ error: 's3_not_configured' })
    const { filename, type = 'application/octet-stream' } = req.body || {}
    const base = safeName(filename || `file-${Date.now()}`)
    const key = `uploads/${new Date().toISOString().slice(0,10)}/${crypto.randomUUID()}-${base}`

    // Nota: NO usar ACL en R2 (suele estar deshabilitado)
    const cmd = new PutObjectCommand({
      Bucket: S3_BUCKET,
      Key: key,
      ContentType: type
    })

    const url = await getSignedUrl(s3, cmd, { expiresIn: 300 }) // 5 minutos
    res.json({ method: 'PUT', url, key, publicUrl: await buildPublicUrl(key) })
  } catch (e) {
    console.error('[presign_failed]', e)
    res.status(500).json({ error: 'presign_failed', detail: String(e?.message || e) })
  }
})

app.post('/api/complete', requireAuth, async (req, res) => {
  try {
    const { key } = req.body || {}
    if (!key) return res.status(400).json({ error: 'key_required' })
    res.json({ ok: true, publicUrl: await buildPublicUrl(key) })
  } catch (e) {
    res.status(500).json({ error: 'complete_failed', detail: String(e?.message || e) })
  }
})

// --- Debug Twilio ---
app.get('/api/debug/twilio/:sid', async (req, res) => {
  try {
    if (!twilioClient) return res.status(500).json({ error: 'no_twilio_client' })
    const msg = await twilioClient.messages(req.params.sid).fetch()
    res.json({
      sid: msg.sid, status: msg.status, to: msg.to, from: msg.from,
      errorCode: msg.errorCode, errorMessage: msg.errorMessage,
      dateCreated: msg.dateCreated, dateSent: msg.dateSent, dateUpdated: msg.dateUpdated,
    })
  } catch (e) {
    res.status(500).json({ error: String(e?.message || e) })
  }
})

app.get('/api/debug/twilio', async (_req, res) => {
  try {
    if (!twilioClient) return res.status(500).json({ error: 'no_twilio_client' })
    const msgs = await twilioClient.messages.list({ limit: 10 })
    res.json(msgs.map(m => ({
      sid: m.sid, status: m.status, to: m.to, from: m.from,
      errorCode: m.errorCode, errorMessage: m.errorMessage,
    })))
  } catch (e) {
    res.status(500).json({ error: String(e?.message || e) })
  }
})

// --- Debug CORS ---
app.get('/api/debug/origins', (req, res) =>
  res.json({ allowed: ORIGINS, requestOrigin: req.headers.origin || null }))

// --- Error handler ---
app.use((err, _req, res, _next) => {
  console.error('[ERR]', err?.message || err)
  res.status(500).json({ error: 'internal_error', detail: String(err?.message || err) })
})

await initDb()
app.listen(parseInt(PORT, 10), () => console.log('Mixtli Backend on :' + PORT))
