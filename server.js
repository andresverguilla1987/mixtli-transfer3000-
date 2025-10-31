// Mixtli Transfer — Backend v2.13t
// SMS-only (Twilio) + OTP + CORS + RateLimit + Purga OTP/Paquetes + S3/R2 presign + Packages
// Por defecto, /api/pack/create devuelve URL **relativa**: "/share/:id"

import 'dotenv/config'
import express from 'express'
import cors from 'cors'
import jwt from 'jsonwebtoken'
import pg from 'pg'
import nodemailer from 'nodemailer'
import twilio from 'twilio'
import rateLimit from 'express-rate-limit'
import crypto from 'crypto'
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3'
import { getSignedUrl } from '@aws-sdk/s3-request-presigner'

// --- Fallback fetch para Node <= 17 ---
if (!globalThis.fetch) {
  const { default: nodeFetch } = await import('node-fetch')
  globalThis.fetch = nodeFetch
}

// -------------------- ENV --------------------
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
  TWILIO_FROM, // +1xxxxxxxxxx

  // S3/R2
  S3_ENDPOINT,                 // https://<account>.r2.cloudflarestorage.com (sin bucket)
  S3_BUCKET,                   // p. ej. mixtlitransfer3000
  S3_REGION = 'auto',
  S3_ACCESS_KEY_ID,
  S3_SECRET_ACCESS_KEY,
  S3_FORCE_PATH_STYLE = 'true', // en R2 => true
  PUBLIC_BASE_URL,              // opcional (sólo para links directos de archivos)
  FORCE_RELATIVE_URLS = 'true', // default: siempre /share/:id

  // Sugerir descarga directa
  CONTENT_DISPOSITION = ''      // ej: 'attachment'
} = process.env

if (!DATABASE_URL) {
  console.error('[FATAL] Missing DATABASE_URL')
  process.exit(1)
}

// -------------------- DB --------------------
const pool = new pg.Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } })

async function safeExec(sql) { try { await pool.query(sql) } catch { /* noop */ } }

async function initDb() {
  await safeExec('CREATE EXTENSION IF NOT EXISTS "pgcrypto";')
  await safeExec('CREATE EXTENSION IF NOT EXISTS "uuid-ossp";')

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      email TEXT,
      phone TEXT,
      plan  TEXT NOT NULL DEFAULT 'FREE',
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

  // índices únicos condicionales para users
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

  // paquetes
  await pool.query(`
    CREATE TABLE IF NOT EXISTS packages (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      owner_uid UUID,
      title TEXT,
      total_size BIGINT DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      expires_at TIMESTAMPTZ
    );
  `)

  await pool.query(`
    CREATE TABLE IF NOT EXISTS package_files (
      id BIGSERIAL PRIMARY KEY,
      package_id UUID REFERENCES packages(id) ON DELETE CASCADE,
      key TEXT NOT NULL,
      filename TEXT,
      size BIGINT,
      content_type TEXT
    );
  `)

  await safeExec(`CREATE INDEX IF NOT EXISTS package_files_pkg_idx ON package_files(package_id);`)
  await safeExec(`CREATE INDEX IF NOT EXISTS packages_expires_idx ON packages(expires_at);`)

  console.log('[DB] ready')
}

// -------------------- Helpers --------------------
const ttlMin = parseInt(OTP_TTL_MIN || '10', 10)
const FORCE_PATH = String(S3_FORCE_PATH_STYLE).toLowerCase() === 'true'

function rand6() { return String(Math.floor(100000 + Math.random() * 900000)) }

function normalizePhone(p) {
  if (!p) return ''
  let s = String(p).trim().replace(/[\s\-\(\)]/g, '')
  if (s.toLowerCase().startsWith('whatsapp:')) s = s.slice('whatsapp:'.length)
  if (!s.startsWith('+') && /^\d{10,15}$/.test(s)) s = '+' + s
  return s
}
function normalizeId(email, phone) {
  const em = (email || '').trim().toLowerCase()
  const ph = normalizePhone(phone || '')
  return em || ph
}

async function createOtp(key) {
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
function authUid(req) {
  try {
    const h = req.headers.authorization || ''
    const tok = h.startsWith('Bearer ') ? h.slice(7) : ''
    if (!tok) return null
    const dec = jwt.verify(tok, JWT_SECRET)
    return dec?.uid || null
  } catch { return null }
}
function requireAuth(req, res, next) {
  const uid = authUid(req)
  if (!uid) return res.status(401).json({ error: 'no_token' })
  req.uid = uid
  next()
}

async function purgeOtps() {
  try { await pool.query('DELETE FROM otps WHERE exp < now()') } catch {}
}
async function purgeExpiredPackages() {
  try {
    await pool.query('DELETE FROM packages WHERE expires_at IS NOT NULL AND expires_at < now()')
  } catch {}
}
setInterval(purgeOtps, 10 * 60 * 1000)          // cada 10 min
setInterval(purgeExpiredPackages, 60 * 60 * 1000) // cada hora

// Mail
let smtpTransport = null
if (SMTP_HOST && SMTP_USER && SMTP_PASS) {
  const portN = parseInt(SMTP_PORT || '587', 10)
  smtpTransport = nodemailer.createTransport({
    host: SMTP_HOST, port: portN, secure: portN === 465, auth: { user: SMTP_USER, pass: SMTP_PASS }
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
        headers: { 'Authorization': `Bearer ${SENDGRID_API_KEY}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      })
      if (!r.ok) console.warn('[MAIL] SendGrid error:', await r.text())
      return
    }
    if (smtpTransport) await smtpTransport.sendMail({ from: SMTP_FROM || SMTP_USER, to, subject, text })
    else console.log('[MAIL:demo]', to, subject, text)
  } catch (e) { console.warn('[MAIL] failed', e?.message || e) }
}

// Twilio
let twilioClient = null
if (TWILIO_ACCOUNT_SID && TWILIO_AUTH_TOKEN) {
  twilioClient = twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
}
async function sendSmsOnly(rawTo, text) {
  const to = normalizePhone(rawTo)
  if (!twilioClient) { console.log('[SMS:demo]', to, text); return }
  if (!TWILIO_FROM) { console.warn('[SMS] Falta TWILIO_FROM'); return }
  try {
    const msg = await twilioClient.messages.create({ to, from: TWILIO_FROM, body: text })
    console.log('[Twilio SID]', msg.sid, 'status=', msg.status)
  } catch (e) { console.warn('[SMS ERROR]', e?.code || e?.status || '', e?.message || String(e)) }
}

// S3/R2
let s3 = null
if (S3_ENDPOINT && S3_BUCKET && S3_ACCESS_KEY_ID && S3_SECRET_ACCESS_KEY) {
  s3 = new S3Client({
    region: S3_REGION,
    endpoint: S3_ENDPOINT, // sin /<bucket>
    credentials: { accessKeyId: S3_ACCESS_KEY_ID, secretAccessKey: S3_SECRET_ACCESS_KEY },
    forcePathStyle: FORCE_PATH
  })
}
function safeName(name = '') { return name.replace(/[^\w\-.]+/g, '_').slice(0, 180) }
async function buildPublicUrl(key) {
  if (PUBLIC_BASE_URL) return `${PUBLIC_BASE_URL.replace(/\/+$/,'')}/${key}`
  const host = S3_ENDPOINT.replace(/^https?:\/\//, '').replace(/\/+$/,'')
  return FORCE_PATH
    ? `${S3_ENDPOINT.replace(/\/+$/,'')}/${S3_BUCKET}/${key}`
    : `https://${S3_BUCKET}.${host}/${key}`
}

// -------------------- App / CORS --------------------
const app = express()
let ORIGINS = []
try { ORIGINS = JSON.parse(ALLOWED_ORIGINS) } catch {}
function isNetlifyPreview(origin) {
  try { return /\.netlify\.app$/i.test(new URL(origin).hostname) } catch { return false }
}
const corsMw = cors({
  origin: (o, cb) => {
    if (!o) return cb(null, true) // curl/Postman/SSR
    if (ORIGINS.includes(o) || isNetlifyPreview(o)) return cb(null, true)
    return cb(new Error('origin_not_allowed'))
  },
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization','x-admin-token','x-cron-token','x-mixtli-token'],
  optionsSuccessStatus: 204
})
app.use((req,res,next)=>corsMw(req,res,(err)=>{
  if (err?.message === 'origin_not_allowed') {
    return res.status(403).json({ error: 'origin_not_allowed', origin: req.headers.origin || null })
  }
  next()
}))
app.options('*', corsMw)
app.set('trust proxy', 1)
app.use(express.json({ limit: '4mb' })) // un poco más holgado para metadatos

// -------------------- Rate-limit OTP --------------------
const otpLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, max: 8,
  standardHeaders: true, legacyHeaders: false,
  skip: (req) => req.method === 'OPTIONS'
})

// -------------------- Rutas base --------------------
app.get('/', (_req, res) => res.type('text/plain').send('OK'))
app.get('/api/health', (_req, res) =>
  res.json({ ok: true, time: new Date().toISOString(), ver: '2.13t', channel: 'sms-only' }))

app.get('/api/auth/whoami', (req, res) => {
  const uid = authUid(req)
  if (!uid) return res.status(401).json({ ok:false })
  res.json({ ok:true, uid })
})

// Aliases sin /api
app.post('/auth/register', (req, _res, next) => { req.url = '/api/auth/register'; next() })
app.post('/auth/verify-otp', (req, _res, next) => { req.url = '/api/auth/verify-otp'; next() })
app.post('/auth/verify', (req, _res, next) => { req.url = '/api/auth/verify-otp'; next() })

// OTP: enviar
app.post('/api/auth/register', otpLimiter, async (req, res) => {
  try {
    const { email='', phone='' } = req.body || {}
    const id = normalizeId(email, phone)
    if (!id) return res.status(400).json({ error: 'email_or_phone_required' })
    const code = await createOtp(id)
    if (email) await sendMail(email.trim().toLowerCase(), 'Tu código Mixtli', `Tu código es: ${code}\nExpira en ${ttlMin} minutos.`)
    else        await sendSmsOnly(phone, `Mixtli: tu código es ${code}. Expira en ${ttlMin} min.`)
    res.json({ ok: true, msg: 'otp_sent' })
  } catch (e) {
    console.error('[register_failed]', e)
    res.status(500).json({ error: 'otp_send_failed' })
  }
})

// OTP: verificar
app.post('/api/auth/verify-otp', async (req, res) => {
  try {
    const { email='', phone='', otp } = req.body || {}
    const id = normalizeId(email, phone)
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
        [email.trim().toLowerCase()]
      )).rows[0]
    } else {
      row = (await pool.query(
        `INSERT INTO users (phone, plan)
         VALUES ($1,'FREE')
         ON CONFLICT (phone) DO UPDATE SET updated_at=now()
         RETURNING id,email,phone,plan,plan_expires_at`,
        [normalizePhone(phone)]
      )).rows[0]
    }
    const token = signToken(row)
    res.json({ token, user: row })
  } catch (e) {
    console.error('[verify_failed]', e)
    res.status(500).json({ error: 'verify_failed' })
  }
})

// -------------------- Presign S3/R2 --------------------
app.post('/api/presign', requireAuth, async (req, res) => {
  try {
    if (!s3) return res.status(500).json({ error: 's3_not_configured' })
    const { filename, type = 'application/octet-stream' } = req.body || {}
    const base = safeName(filename || `file-${Date.now()}`)
    const key  = `uploads/${new Date().toISOString().slice(0,10)}/${crypto.randomUUID()}-${base}`

    const params = { Bucket: S3_BUCKET, Key: key, ContentType: type }
    if (CONTENT_DISPOSITION) params.ContentDisposition = CONTENT_DISPOSITION

    const cmd = new PutObjectCommand(params) // R2: no usar ACL
    const url = await getSignedUrl(s3, cmd, { expiresIn: 300 }) // 5 min
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
    console.error('[complete_failed]', e)
    res.status(500).json({ error: 'complete_failed' })
  }
})

// -------------------- PACKAGES --------------------
app.post('/api/pack/create', requireAuth, async (req, res) => {
  try {
    const { title = 'Mis archivos', ttlDays = 30, files = [] } = req.body || {}
    if (!Array.isArray(files) || files.length === 0) {
      return res.status(400).json({ error: 'no_files' })
    }
    const ttl = Math.min(Math.max(parseInt(ttlDays || 30, 10), 1), 180)
    const totalSize = files.reduce((a, f) => a + (Number(f.size) || 0), 0)

    const r = await pool.query(
      `INSERT INTO packages (owner_uid, title, total_size, expires_at)
       VALUES ($1,$2,$3, now() + ($4 || ' days')::interval)
       RETURNING id, expires_at`,
      [req.uid, title, totalSize, ttl]
    )
    const pid = r.rows[0].id

    // bulk insert files
    const values = []
    const params = []
    files.forEach(f => {
      params.push(pid, f.key, f.name || null, Number(f.size) || 0, f.type || null)
      values.push(
        `($${params.length-4},$${params.length-3},$${params.length-2},$${params.length-1},$${params.length})`
      )
    })
    await pool.query(
      `INSERT INTO package_files (package_id, key, filename, size, content_type)
       VALUES ${values.join(',')}`,
      params
    )

    const sharePath = `/share/${pid}`
    const relative = String(FORCE_RELATIVE_URLS).toLowerCase() === 'true'
    const url = relative
      ? sharePath
      : ((PUBLIC_BASE_URL || '') ? (PUBLIC_BASE_URL.replace(/\/+$/,'') + sharePath) : sharePath)

    res.json({ ok: true, id: pid, url, expires_at: r.rows[0].expires_at })
  } catch (e) {
    console.error('[pack_create_failed]', e)
    res.status(500).json({ error: 'pack_create_failed' })
  }
})

// JSON del paquete (para previews/embeds)
app.get('/api/pack/:id', async (req, res) => {
  try {
    const id = req.params.id
    const p = await pool.query('SELECT * FROM packages WHERE id=$1', [id])
    if (!p.rows.length) return res.status(404).json({ error: 'not_found' })
    const f = await pool.query(
      `SELECT key, filename, size, content_type FROM package_files
       WHERE package_id=$1 ORDER BY id`, [id]
    )
    const files = await Promise.all(
      f.rows.map(async r => ({
        name: r.filename || 'file',
        size: Number(r.size) || 0,
        type: r.content_type,
        url: await buildPublicUrl(r.key)
      }))
    )
    res.json({ id, title: p.rows[0].title, total_size: Number(p.rows[0].total_size) || 0,
      expires_at: p.rows[0].expires_at, files })
  } catch (e) {
    console.error('[pack_fetch_failed]', e)
    res.status(500).json({ error: 'pack_fetch_failed' })
  }
})

// Página pública simple de descarga
app.get('/share/:id', async (req, res) => {
  try {
    const id = req.params.id
    const p = await pool.query('SELECT * FROM packages WHERE id=$1', [id])
    if (!p.rows.length) return res.status(404).type('text/plain').send('Paquete no encontrado')

    const f = await pool.query(
      'SELECT key, filename, size FROM package_files WHERE package_id=$1 ORDER BY id', [id]
    )
    const items = await Promise.all(f.rows.map(async r => {
      const url = await buildPublicUrl(r.key)
      const name = (r.filename || 'file').replace(/</g,'&lt;').replace(/>/g,'&gt;')
      const mb = (Number(r.size||0)/1048576).toFixed(2)
      return `<li><a href="${url}" target="_blank" rel="noopener">${name}</a> — ${mb} MB</li>`
    }))

    res.type('html').send(`<!doctype html><meta charset="utf-8">
      <title>${(p.rows[0].title || 'Descargas').replace(/</g,'&lt;').replace(/>/g,'&gt;')}</title>
      <meta name="viewport" content="width=device-width,initial-scale=1" />
      <div style="font-family:system-ui;padding:24px;max-width:820px;margin:auto;color:#e5e7eb;background:#0b0f17">
        <h1 style="margin:0 0 8px;font-size:28px;color:#fff">${(p.rows[0].title || 'Descargas').replace(/</g,'&lt;').replace(/>/g,'&gt;')}</h1>
        <p style="margin:0 0 16px;color:#9ca3af">Expira: ${p.rows[0].expires_at}</p>
        <ul style="line-height:1.9">${items.join('')}</ul>
      </div>`)
  } catch (e) {
    console.error('[share_render_failed]', e)
    res.status(500).type('text/plain').send('Error interno')
  }
})

// -------------------- Debug --------------------
app.get('/api/debug/twilio/:sid', async (req, res) => {
  try {
    if (!twilioClient) return res.status(500).json({ error: 'no_twilio_client' })
    const msg = await twilioClient.messages(req.params.sid).fetch()
    res.json({
      sid: msg.sid, status: msg.status, to: msg.to, from: msg.from,
      errorCode: msg.errorCode, errorMessage: msg.errorMessage,
      dateCreated: msg.dateCreated, dateSent: msg.dateSent, dateUpdated: msg.dateUpdated
    })
  } catch (e) { res.status(500).json({ error: String(e?.message || e) }) }
})
app.get('/api/debug/twilio', async (_req, res) => {
  try {
    if (!twilioClient) return res.status(500).json({ error: 'no_twilio_client' })
    const msgs = await twilioClient.messages.list({ limit: 10 })
    res.json(msgs.map(m => ({
      sid: m.sid, status: m.status, to: m.to, from: m.from,
      errorCode: m.errorCode, errorMessage: m.errorMessage
    })))
  } catch (e) { res.status(500).json({ error: String(e?.message || e) }) }
})
app.get('/api/debug/origins', (req, res) =>
  res.json({ allowed: ORIGINS, requestOrigin: req.headers.origin || null }))

// Error global
app.use((err,_req,res,_next)=>{
  console.error('[ERR]', err?.message || err)
  res.status(500).json({ error: 'internal_error', detail: String(err?.message || err) })
})

// Boot
await initDb()
app.listen(parseInt(PORT,10), () => console.log('Mixtli Backend on :' + PORT))
