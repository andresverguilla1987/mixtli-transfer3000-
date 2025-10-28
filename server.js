// Mixtli Transfer – Backend (OTP + Health) v2.8
// CORS + Email (SendGrid/SMTP) + SMS/WhatsApp (Twilio) + RateLimit + Purga OTP
// Node 18+ recomendado (trae fetch). Si no, activamos fallback.

import 'dotenv/config'
import express from 'express'
import cors from 'cors'
import jwt from 'jsonwebtoken'
import pg from 'pg'
import nodemailer from 'nodemailer'
import twilio from 'twilio'
import rateLimit from 'express-rate-limit'

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

  // Email
  SENDGRID_API_KEY,
  SENDGRID_FROM,
  SMTP_HOST,
  SMTP_PORT = '587',
  SMTP_USER,
  SMTP_PASS,
  SMTP_FROM,

  // CORS
  ALLOWED_ORIGINS = '["http://localhost:8888","http://localhost:5173","http://127.0.0.1:5173","http://localhost:3000","https://lighthearted-froyo-9dd448.netlify.app"]',

  // Twilio
  TWILIO_ACCOUNT_SID,
  TWILIO_AUTH_TOKEN,
  TWILIO_FROM,              // ej: +12025550123 (SMS)
  TWILIO_WHATSAPP_FROM,     // ej: whatsapp:+14155238886 (sandbox) o whatsapp:+<tu-num-BAA>
  TWILIO_PREFER_WHATSAPP = '0'
} = process.env

if (!DATABASE_URL) { console.error('[FATAL] Missing DATABASE_URL'); process.exit(1) }

// Render/Postgres requiere SSL (evita self-signed).
const pool = new pg.Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }
})

// ---------------- DB bootstrap ----------------
async function initDb() {
  try { await pool.query('CREATE EXTENSION IF NOT EXISTS "pgcrypto";') }
  catch (e) { console.warn('[DB] pgcrypto ext no disponible:', e?.message || e) }

  try { await pool.query('CREATE EXTENSION IF NOT EXISTS "uuid-ossp";') }
  catch (e) { console.warn('[DB] uuid-ossp ext no disponible:', e?.message || e) }

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

// ---------------- OTP helpers ----------------
function rand6() {
  return String(Math.floor(100000 + Math.random() * 900000))
}

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

// Purga periódica de OTPs vencidos
async function purgeOtps() {
  try { await pool.query('DELETE FROM otps WHERE exp < now()') }
  catch (e) { console.warn('[OTP purge] error:', e?.message || e) }
}
setInterval(purgeOtps, 10 * 60 * 1000) // cada 10 minutos

// ---------------- Mail (SendGrid/SMTP) ----------------
let smtpTransport = null
if (SMTP_HOST && SMTP_USER && SMTP_PASS) {
  const portN = parseInt(SMTP_PORT || '587', 10)
  smtpTransport = nodemailer.createTransport({
    host: SMTP_HOST,
    port: portN,
    secure: portN === 465,
    auth: { user: SMTP_USER, pass: SMTP_PASS }
  })
}

async function sendMail(to, subject, text) {
  try {
    if (SENDGRID_API_KEY && SENDGRID_FROM) {
      const body = {
        personalizations: [{ to: [{ email: to }] }],
        from: { email: SENDGRID_FROM },
        subject,
        content: [{ type: 'text/plain', value: text }]
      }
      const r = await fetch('https://api.sendgrid.com/v3/mail/send', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${SENDGRID_API_KEY}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(body)
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

// ---------------- SMS / WhatsApp (Twilio) ----------------
let twilioClient = null
if (TWILIO_ACCOUNT_SID && TWILIO_AUTH_TOKEN) {
  twilioClient = twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
}

function normalizePhone(p) {
  if (!p) return ''
  // quita espacios, guiones y paréntesis
  return String(p).replace(/[\s\-\(\)]/g, '')
}

// Decide canal y manda
async function sendSmsOrWhatsapp(rawTo, text) {
  const toRaw = normalizePhone(rawTo)

  if (!twilioClient) { console.log('[SMS:demo]', toRaw, text); return }

  let to = toRaw
  let from = TWILIO_FROM

  const looksWhatsApp = toRaw.startsWith('whatsapp:')
  if (looksWhatsApp || (TWILIO_PREFER_WHATSAPP === '1' && TWILIO_WHATSAPP_FROM)) {
    if (!looksWhatsApp && toRaw.startsWith('+')) to = `whatsapp:${toRaw}`
    from = TWILIO_WHATSAPP_FROM
  }

  if (!from) { console.warn('[SMS] Falta TWILIO_FROM/TWILIO_WHATSAPP_FROM'); return }

  // LOG de depuración para confirmar canal
  console.log('[WA/SMS] to=', to, 'from=', from, 'preferWA=', TWILIO_PREFER_WHATSAPP)

  try {
    const msg = await twilioClient.messages.create({ to, from, body: text })
    console.log('[Twilio SID]', msg.sid, 'status=', msg.status)
  } catch (e) {
    console.warn('[SMS] fallo', e?.message || e)
  }
}

// ---------------- App / CORS ----------------
const app = express()

let ORIGINS = []
try { ORIGINS = JSON.parse(ALLOWED_ORIGINS) } catch { ORIGINS = [] }

// helper para previews de Netlify (*.netlify.app)
function isNetlifyPreview(origin) {
  try {
    const h = new URL(origin).hostname
    return /\.netlify\.app$/i.test(h)
  } catch { return false }
}

const corsMw = cors({
  origin: (o, cb) => {
    if (!o) return cb(null, true) // Postman / curl / SSR
    if (ORIGINS.includes(o) || isNetlifyPreview(o)) return cb(null, true)
    return cb(new Error('origin_not_allowed'))
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-admin-token', 'x-cron-token', 'x-mixtli-token'],
  optionsSuccessStatus: 204
})
app.use(corsMw)
app.options('*', corsMw)

// 👇 Fix para express-rate-limit v7 en Render (1 proxy delante)
app.set('trust proxy', 1)
app.use(express.json({ limit: '2mb' }))

// ---------------- Rate-limit OTP ----------------
const otpLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 min
  max: 8,                  // 8 intentos por IP
  standardHeaders: true,
  legacyHeaders: false,
  // no contar preflight
  skip: (req) => req.method === 'OPTIONS',
})

// ---------------- Routes ----------------
app.get('/', (_req, res) => res.type('text/plain').send('OK'))
app.get('/api/health', (_req, res) => res.json({ ok: true, time: new Date().toISOString() }))

// Enviar OTP (email o phone)
app.post('/api/auth/register', otpLimiter, async (req, res) => {
  try {
    const { email, phone } = req.body || {}
    const id = (email && String(email).toLowerCase()) || (phone && String(phone)) || ''
    if (!id) return res.status(400).json({ error: 'email_or_phone_required' })

    const code = await createOtp(id, OTP_TTL_MIN)

    if (email) {
      await sendMail(
        id,
        'Tu código Mixtli',
        `Tu código es: ${code}\nExpira en ${OTP_TTL_MIN} minutos.`
      )
    } else {
      await sendSmsOrWhatsapp(phone, `Mixtli: tu código es ${code}. Expira en ${OTP_TTL_MIN} min.`)
    }

    res.json({ ok: true, msg: 'otp_sent' })
  } catch (e) {
    console.error(e)
    res.status(500).json({ error: 'otp_send_failed' })
  }
})

// Alias legacy
app.post('/api/auth/verify', (req, _res, next) => {
  console.log('[ALIAS] /api/auth/verify -> /api/auth/verify-otp')
  req.url = '/api/auth/verify-otp'
  next()
})

// Verificar OTP y upsert usuario
app.post('/api/auth/verify-otp', async (req, res) => {
  try {
    console.log('[VERIFY-OTP] body:', req.body)
    const { email, phone, otp } = req.body || {}
    const id = (email && String(email).toLowerCase()) || (phone && String(phone)) || ''
    if (!id || !otp) return res.status(400).json({ error: 'need_id_and_otp' })

    const ok = await verifyOtpDb(id, otp)
    if (!ok) return res.status(400).json({ error: 'otp_invalid' })

    let row
    if (email) {
      const r = await pool.query(
        `INSERT INTO users (email, plan)
         VALUES ($1,'FREE')
         ON CONFLICT (email) DO UPDATE SET updated_at=now()
         RETURNING id,email,phone,plan,plan_expires_at`,
        [email.toLowerCase()]
      )
      row = r.rows[0]
    } else {
      const r = await pool.query(
        `INSERT INTO users (phone, plan)
         VALUES ($1,'FREE')
         ON CONFLICT (phone) DO UPDATE SET updated_at=now()
         RETURNING id,email,phone,plan,plan_expires_at`,
        [phone]
      )
      row = r.rows[0]
    }

    const token = signToken(row)
    res.json({ token, user: row })
  } catch (e) {
    console.error(e)
    res.status(500).json({ error: 'verify_failed' })
  }
})

// Error handler
app.use((err, _req, res, _next) => {
  console.error('[ERR]', err?.message || err)
  res.status(500).json({ error: 'internal_error', detail: String(err?.message || err) })
})

await initDb()
app.listen(parseInt(PORT, 10), () => console.log('Mixtli Backend on :' + PORT))
