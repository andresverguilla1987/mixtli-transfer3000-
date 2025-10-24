// MixtliTransfer3000 — Sealed Server + Anon FREE (ESM fixed)
import 'dotenv/config'
import express from 'express'
import cors from 'cors'
import { randomUUID, createHash } from 'node:crypto'
import jwt from 'jsonwebtoken'
import pg from 'pg'
import { S3Client, PutObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3'
import { getSignedUrl } from '@aws-sdk/s3-request-presigner'

const SEALED = {
  S3_ENDPOINT: 'https://8351c372dedf0e354a3196aff085f0ae.r2.cloudflarestorage.com',
  S3_BUCKET: 'mixtlitransfer3000',
  S3_REGION: 'auto',
  S3_FORCE_PATH_STYLE: true,
  ALLOWED_ORIGINS: [
    'https://lighthearted-froyo-9dd448.netlify.app',
    'http://localhost:8888'
  ]
}

const {
  PORT = 10000,
  S3_ACCESS_KEY_ID,
  S3_SECRET_ACCESS_KEY,
  DATABASE_URL,
  JWT_SECRET = 'change_me',
  OTP_TTL_MIN = '10',
  FREE_MAX_UPLOAD_MB = '3584',
  FREE_LINK_TTL_DEFAULT_DAYS = '3',
  FREE_LINK_TTL_MAX_DAYS = '30',
  FREE_MAX_LINKS_PER_30D = '10',
  PRO_MAX_PERIOD_GB = '400',
  PRO_PERIOD_DAYS = '30',
  PRO_LINK_TTL_DAYS = '7',
  PROMAX_PERIOD_DAYS = '30',
  PROMAX_LINK_TTL_DAYS = '22',
  UPLOAD_URL_TTL_SECONDS = '3600',
  DOWNLOAD_URL_TTL_SECONDS_MAX = '86400'
} = process.env

if (!SEALED.S3_ENDPOINT || !SEALED.S3_BUCKET || !S3_ACCESS_KEY_ID || !S3_SECRET_ACCESS_KEY) {
  console.error('[FATAL] Missing R2 credentials or sealed config'); process.exit(1)
}
if (!DATABASE_URL) { console.error('[FATAL] Missing DATABASE_URL'); process.exit(1) }

const MB = 1024 * 1024
const pool = new pg.Pool({ connectionString: DATABASE_URL })
const s3 = new S3Client({
  region: SEALED.S3_REGION,
  endpoint: SEALED.S3_ENDPOINT,
  credentials: { accessKeyId: S3_ACCESS_KEY_ID, secretAccessKey: S3_SECRET_ACCESS_KEY },
  forcePathStyle: !!SEALED.S3_FORCE_PATH_STYLE
})

const app = express()
app.use(cors({
  origin: (o, cb) => {
    if (!o) return cb(null, true)
    if (SEALED.ALLOWED_ORIGINS.includes(o)) return cb(null, true)
    cb(new Error('origin_not_allowed'))
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-mixtli-token']
}))
app.use(express.json({ limit: '1mb' }))

// best-effort migration
pool.query(`ALTER TABLE links ADD COLUMN IF NOT EXISTS anon_ip text`).catch(() => {})

app.get('/api/health', (_req, res) =>
  res.json({ ok: true, service: 'mixtlitransfer3000', time: new Date().toISOString() })
)

// ---------- auth helpers ----------
const otpStore = new Map()
function setOtp(key) {
  const code = String(Math.floor(100000 + Math.random() * 900000))
  const exp = Date.now() + Number(OTP_TTL_MIN) * 60 * 1000
  otpStore.set(key, { code, exp })
  console.log('[OTP]', key, code)
}
function verifyOtp(key, code) {
  const row = otpStore.get(key)
  if (!row) return false
  if (Date.now() > row.exp) { otpStore.delete(key); return false }
  const ok = row.code === String(code)
  if (ok) otpStore.delete(key)
  return ok
}
function signToken(user) {
  return jwt.sign({ uid: user.id, plan: user.plan }, JWT_SECRET, { expiresIn: '30d' })
}
async function authOptional(req, _res, next) {
  const a = req.headers.authorization || ''
  const t = a.startsWith('Bearer ') ? a.slice(7) : ''
  if (!t) return next()
  try {
    const p = jwt.verify(t, JWT_SECRET)
    const { rows } = await pool.query('SELECT id,email,phone,plan FROM users WHERE id=$1', [p.uid])
    req.user = rows[0] || null
  } catch (_e) {
    req.user = null
  } finally {
    next()
  }
}
async function authRequired(req, res, next) {
  await authOptional(req, res, () => {})
  if (!req.user) return res.status(401).json({ error: 'auth_required' })
  next()
}

// ---------- auth endpoints ----------
app.post('/api/auth/register', async (req, res) => {
  const { email, phone } = req.body || {}
  const id = (email && String(email).toLowerCase()) || (phone && String(phone)) || ''
  if (!id) return res.status(400).json({ error: 'email_or_phone_required' })
  setOtp(id)
  res.json({ ok: true, msg: 'otp_sent' })
})

app.post('/api/auth/verify-otp', async (req, res) => {
  const { email, phone, otp } = req.body || {}
  const id = (email && String(email).toLowerCase()) || (phone && String(phone)) || ''
  if (!id || !otp) return res.status(400).json({ error: 'need_id_and_otp' })
  if (!verifyOtp(id, otp)) return res.status(400).json({ error: 'otp_invalid' })

  const c = await pool.connect()
  try {
    await c.query('BEGIN')
    let row
    if (email) {
      const r = await c.query(
        `INSERT INTO users (email,plan) VALUES ($1,'FREE')
         ON CONFLICT (email) DO UPDATE SET updated_at=now()
         RETURNING id,email,phone,plan`,
        [email.toLowerCase()]
      )
      row = r.rows[0]
    } else {
      const r = await c.query(
        `INSERT INTO users (phone,plan) VALUES ($1,'FREE')
         ON CONFLICT (phone) DO UPDATE SET updated_at=now()
         RETURNING id,email,phone,plan`,
        [phone]
      )
      row = r.rows[0]
    }
    await c.query('COMMIT')
    const token = signToken(row)
    res.json({ token, user: row })
  } catch (e) {
    await c.query('ROLLBACK')
    console.error(e)
    res.status(500).json({ error: 'verify_failed' })
  } finally {
    c.release()
  }
})

// ---------- utils ----------
function num(x) { return Math.max(0, parseInt(String(x || '0'), 10) || 0) }
function clamp(n, a, b) { return Math.max(a, Math.min(b, n)) }
function extOf(f = '') { const i = f.lastIndexOf('.'); return i > -1 ? f.slice(i + 1).toLowerCase() : '' }
function clientIp(req) {
  const xf = req.headers['x-forwarded-for']
  const ip = (Array.isArray(xf) ? xf[0] : (xf || '')).split(',')[0].trim() || req.ip || '0.0.0.0'
  return ip
}
// FIX: sin require (ESM). Usa createHash importado arriba
function hashIp(ip, salt = process.env.IP_SALT || process.env.IP_HASH_SECRET || '') {
  return createHash('sha256').update(String(salt)).update(String(ip)).digest('hex').slice(0, 32)
}

const FREECFG = {
  sizeCap: num(FREE_MAX_UPLOAD_MB) * MB,
  ttlDefaultDays: num(FREE_LINK_TTL_DEFAULT_DAYS),
  ttlMaxDays: num(FREE_LINK_TTL_MAX_DAYS),
  maxLinks30d: num(FREE_MAX_LINKS_PER_30D)
}
const PROCFG = {
  capBytesPerPeriod: num(PRO_MAX_PERIOD_GB) * 1024 * 1024 * 1024,
  ttlDays: num(PRO_LINK_TTL_DAYS)
}
const PMCFG = { ttlDays: num(PROMAX_LINK_TTL_DAYS) }

// ---------- presign ----------
app.post('/api/presign', authOptional, async (req, res) => {
  try {
    const user = req.user
    let { filename, contentType, contentLength, plan, durationDays } = req.body || {}
    filename = String(filename || '')
    contentType = String(contentType || 'application/octet-stream')
    contentLength = Number(contentLength || 0)
    plan = String(plan || (user?.plan || 'FREE')).toUpperCase()

    if (plan === 'FREE' && !user) {
      const ttlDays = clamp(num(durationDays || FREECFG.ttlDefaultDays), FREECFG.ttlDefaultDays, FREECFG.ttlMaxDays)
      if (!filename || !contentType || !contentLength) return res.status(400).json({ error: 'bad_params' })
      if (contentLength > FREECFG.sizeCap) return res.status(413).json({ error: 'file_too_large', maxBytes: FREECFG.sizeCap })

      const anon = hashIp(clientIp(req))
      const { rows } = await pool.query(
        `SELECT COUNT(*)::int AS cnt FROM links WHERE anon_ip=$1 AND created_at>= now()-INTERVAL '30 days'`,
        [anon]
      )
      if (Number(rows[0]?.cnt || 0) >= FREECFG.maxLinks30d) {
        return res.status(429).json({ error: 'free_link_count_exceeded', limit: FREECFG.maxLinks30d })
      }

      const ext = extOf(filename)
      const day = new Date().toISOString().slice(0, 10)
      const key = `mt/FREE/${day}/${randomUUID()}${ext ? '.' + ext : ''}`

      const c = await pool.connect()
      try {
        await c.query('BEGIN')
        await c.query(
          `INSERT INTO links (user_id,anon_ip,plan,key,filename,content_type,size_bytes,expires_at,active)
           VALUES (NULL,$1,'FREE',$2,$3,$4,$5, now()+($6||' days')::interval, true)`,
          [anon, key, filename, contentType, contentLength, ttlDays]
        )
        await c.query('COMMIT')
      } catch (e) {
        await c.query('ROLLBACK')
        throw e
      } finally {
        c.release()
      }

      const put = new PutObjectCommand({
        Bucket: SEALED.S3_BUCKET,
        Key: key,
        ContentType: contentType,
        Metadata: { 'x-plan': 'FREE', 'x-origin': 'mixtli' }
      })
      const uploadUrl = await getSignedUrl(s3, put, { expiresIn: num(UPLOAD_URL_TTL_SECONDS) })

      const get = new GetObjectCommand({
        Bucket: SEALED.S3_BUCKET,
        Key: key,
        ResponseContentDisposition: `attachment; filename="${filename}"`
      })
      const downloadUrl = await getSignedUrl(s3, get, { expiresIn: num(DOWNLOAD_URL_TTL_SECONDS_MAX) })

      return res.json({
        key,
        uploadUrl,
        uploadHeaders: { 'Content-Type': contentType },
        downloadUrl,
        expiresInSeconds: ttlDays * 24 * 3600
      })
    }

    if (!user) return res.status(401).json({ error: 'auth_required' })

    const { rows: agg } = await pool.query(
      `SELECT COALESCE(SUM(size_bytes),0) AS bytes, COUNT(*) AS count
       FROM links WHERE user_id=$1 AND created_at>= now()-INTERVAL '30 days'`,
      [user.id]
    )
    const usedBytes = Number(agg[0]?.bytes || 0)
    const usedCount = Number(agg[0]?.count || 0)

    if (plan === 'FREE') {
      if (usedCount >= FREECFG.maxLinks30d) {
        return res.status(429).json({ error: 'free_link_count_exceeded', limit: FREECFG.maxLinks30d })
      }
    } else if (plan === 'PRO') {
      if (usedBytes + contentLength > PROCFG.capBytesPerPeriod) {
        return res.status(429).json({ error: 'pro_bytes_quota_exceeded', limitBytes: PROCFG.capBytesPerPeriod, usedBytes })
      }
    }

    const ttlDays =
      plan === 'PRO' ? PROCFG.ttlDays :
      (plan === 'PROMAX' ? PMCFG.ttlDays :
        clamp(num(durationDays || FREECFG.ttlDefaultDays), FREECFG.ttlDefaultDays, FREECFG.ttlMaxDays))

    if (!filename || !contentType || !contentLength) return res.status(400).json({ error: 'bad_params' })
    if (plan === 'FREE' && contentLength > FREECFG.sizeCap) {
      return res.status(413).json({ error: 'file_too_large', maxBytes: FREECFG.sizeCap })
    }

    const ext = extOf(filename)
    const day = new Date().toISOString().slice(0, 10)
    const key = `mt/${plan}/${day}/${randomUUID()}${ext ? '.' + ext : ''}`

    const c = await pool.connect()
    try {
      await c.query('BEGIN')
      await c.query(
        `INSERT INTO links (user_id,plan,key,filename,content_type,size_bytes,expires_at,active)
         VALUES ($1,$2,$3,$4,$5,$6, now()+($7||' days')::interval, true)`,
        [user.id, plan, key, filename, contentType, contentLength, ttlDays]
      )
      await c.query('COMMIT')
    } catch (e) {
      await c.query('ROLLBACK')
      throw e
    } finally {
      c.release()
    }

    const put = new PutObjectCommand({
      Bucket: SEALED.S3_BUCKET,
      Key: key,
      ContentType: contentType,
      Metadata: { 'x-plan': plan, 'x-origin': 'mixtli' }
    })
    const uploadUrl = await getSignedUrl(s3, put, { expiresIn: num(UPLOAD_URL_TTL_SECONDS) })

    const get = new GetObjectCommand({
      Bucket: SEALED.S3_BUCKET,
      Key: key,
      ResponseContentDisposition: `attachment; filename="${filename}"`
    })
    const downloadUrl = await getSignedUrl(s3, get, { expiresIn: num(DOWNLOAD_URL_TTL_SECONDS_MAX) })

    res.json({
      key,
      uploadUrl,
      uploadHeaders: { 'Content-Type': contentType },
      downloadUrl,
      expiresInSeconds: ttlDays * 24 * 3600
    })
  } catch (e) {
    console.error(e)
    res.status(500).json({ error: 'presign_failed', detail: String(e) })
  }
})

app.listen(PORT, () => console.log('MixtliTransfer3000 listening on :' + PORT))
