// MixtliTransfer3000 Backend v2.1.3 — initDb sin FK + fixes (root 200, CORS robusto, trust proxy)
import 'dotenv/config'
import express from 'express'
import cors from 'cors'
import { randomUUID, createHash } from 'node:crypto'
import jwt from 'jsonwebtoken'
import pg from 'pg'
import { S3Client, PutObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3'
import { getSignedUrl } from '@aws-sdk/s3-request-presigner'

// ---------- Helpers ----------
const parseJsonArray = (val, fallback) => {
  try {
    if (Array.isArray(val)) return val
    if (typeof val === 'string') {
      const t = val.trim()
      if (t.startsWith('[')) return JSON.parse(t)
      if (t.includes(',')) return t.split(',').map(s => s.trim()).filter(Boolean)
      if (t) return [t]
    }
  } catch {}
  return fallback
}

// ---------- SEALED/ENV ----------
const SEALED = {
  S3_ENDPOINT: process.env.S3_ENDPOINT || 'https://8351c372dedf0e354a3196aff085f0ae.r2.cloudflarestorage.com',
  S3_BUCKET: process.env.S3_BUCKET || 'mixtlitransfer3000',
  S3_REGION: process.env.S3_REGION || 'auto',
  S3_FORCE_PATH_STYLE: (process.env.S3_FORCE_PATH_STYLE || 'true') === 'true',
  ALLOWED_ORIGINS: parseJsonArray(process.env.ALLOWED_ORIGINS, [
    'https://lighthearted-froyo-9dd448.netlify.app',
    'http://localhost:8888'
  ])
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
  PRO_LINK_TTL_DAYS = '7',
  PROMAX_LINK_TTL_DAYS = '22',
  UPLOAD_URL_TTL_SECONDS = '3600',
  DOWNLOAD_URL_TTL_SECONDS_MAX = '86400',
  PUBLIC_BASE_URL
} = process.env

if (!SEALED.S3_ENDPOINT || !SEALED.S3_BUCKET || !S3_ACCESS_KEY_ID || !S3_SECRET_ACCESS_KEY) {
  console.error('[FATAL] Missing R2 credentials'); process.exit(1)
}
if (!DATABASE_URL) { console.error('[FATAL] Missing DATABASE_URL'); process.exit(1) }

// ---------- Clients ----------
const MB = 1024 * 1024
const pool = new pg.Pool({ connectionString: DATABASE_URL })
const s3 = new S3Client({
  region: SEALED.S3_REGION,
  endpoint: SEALED.S3_ENDPOINT,
  credentials: { accessKeyId: S3_ACCESS_KEY_ID, secretAccessKey: S3_SECRET_ACCESS_KEY },
  forcePathStyle: !!SEALED.S3_FORCE_PATH_STYLE
})

// ---------- Small utils ----------
const num = (x) => Math.max(0, parseInt(String(x ?? '0'), 10) || 0)
const clamp = (n, a, b) => Math.max(a, Math.min(b, n))
const extOf = (f = '') => { const i = f.lastIndexOf('.'); return i > -1 ? f.slice(i + 1).toLowerCase() : '' }
const clientIp = (req) => {
  const xf = req.headers['x-forwarded-for']
  const ip = (Array.isArray(xf) ? xf[0] : (xf || '')).split(',')[0].trim() || req.ip || '0.0.0.0'
  return ip
}
const hashIp = (ip, salt = process.env.IP_SALT || process.env.IP_HASH_SECRET || '') =>
  createHash('sha256').update(String(salt)).update(String(ip)).digest('hex').slice(0, 32)

// ---------- Plans ----------
const FREECFG  = { sizeCap: num(FREE_MAX_UPLOAD_MB) * MB, ttlDefaultDays: num(FREE_LINK_TTL_DEFAULT_DAYS), ttlMaxDays: num(FREE_LINK_TTL_MAX_DAYS), maxLinks30d: num(FREE_MAX_LINKS_PER_30D) }
const PROCFG   = { capBytesPerPeriod: num(PRO_MAX_PERIOD_GB) * 1024 * 1024 * 1024, ttlDays: num(PRO_LINK_TTL_DAYS) }
const PMCFG    = { ttlDays: num(PROMAX_LINK_TTL_DAYS) }

// ---------- DB: init sin FKs (anti UUID/BIGINT) ----------
async function initDb () {
  await pool.query(`CREATE EXTENSION IF NOT EXISTS "pgcrypto";`)
  await pool.query(`CREATE EXTENSION IF NOT EXISTS "uuid-ossp";`)

  const q = await pool.query(`
    SELECT data_type FROM information_schema.columns
    WHERE table_schema='public' AND table_name='users' AND column_name='id' LIMIT 1
  `)
  let usersIdType = q.rows[0]?.data_type // 'uuid'|'bigint'|undefined

  if (!usersIdType) {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        email TEXT UNIQUE,
        phone TEXT UNIQUE,
        plan  TEXT NOT NULL DEFAULT 'FREE',
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
    `)
    usersIdType = 'uuid'
  }

  const USER_ID_SQLTYPE = (usersIdType === 'bigint') ? 'BIGINT' : 'UUID'

  await pool.query(`
    CREATE TABLE IF NOT EXISTS links (
      id BIGSERIAL PRIMARY KEY,
      user_id ${USER_ID_SQLTYPE},
      anon_ip TEXT,
      plan TEXT NOT NULL,
      key  TEXT NOT NULL,
      filename TEXT NOT NULL,
      content_type TEXT NOT NULL,
      size_bytes BIGINT NOT NULL DEFAULT 0,
      expires_at TIMESTAMPTZ NOT NULL,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `)

  await pool.query(`
    CREATE TABLE IF NOT EXISTS packages (
      id TEXT PRIMARY KEY,
      user_id ${USER_ID_SQLTYPE},
      anon_ip TEXT,
      plan TEXT NOT NULL DEFAULT 'FREE',
      title TEXT,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      downloads INT NOT NULL DEFAULT 0,
      download_limit INT
    );
  `)

  await pool.query(`
    CREATE TABLE IF NOT EXISTS package_items (
      id BIGSERIAL PRIMARY KEY,
      package_id TEXT,
      key TEXT NOT NULL,
      filename TEXT NOT NULL,
      content_type TEXT NOT NULL,
      size_bytes BIGINT NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      downloads INT NOT NULL DEFAULT 0
    );
  `)

  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS idx_links_key_unique ON links(key);`)
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_links_user_created ON links(user_id, created_at DESC);`)
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_links_anon_created ON links(anon_ip, created_at DESC);`)
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_links_expires ON links(expires_at);`)
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_pkg_created ON packages(created_at DESC);`)
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_pkg_items_pkg ON package_items(package_id);`)

  console.log('[DB] schema ready (no-FK mode, user_id type = ' + USER_ID_SQLTYPE + ')')
}

// ---------- App ----------
const app = express()
app.set('trust proxy', true)

// Root para health de Render (200 OK siempre)
app.get('/', (_req, res) => {
  res.json({ ok: true, name: 'MixtliTransfer3000', docs: '/api/health', time: new Date().toISOString() })
})

app.use(cors({
  origin: (o, cb) => { if (!o) return cb(null, true); if (SEALED.ALLOWED_ORIGINS.includes(o)) return cb(null, true); cb(new Error('origin_not_allowed')) },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-mixtli-token']
}))
app.use(express.json({ limit: '2mb' }))

app.get('/api/health', (_req, res) =>
  res.json({ ok: true, service: 'mixtlitransfer3000', time: new Date().toISOString() })
)

// ---------- Auth-lite ----------
const otpStore = new Map()
function setOtp (key) {
  const code = String(Math.floor(100000 + Math.random() * 900000))
  const exp = Date.now() + Number(OTP_TTL_MIN) * 60 * 1000
  otpStore.set(key, { code, exp })
  console.log('[OTP]', key, code)
}
function verifyOtp (key, code) {
  const row = otpStore.get(key); if (!row) return false
  if (Date.now() > row.exp) { otpStore.delete(key); return false }
  const ok = row.code === String(code); if (ok) otpStore.delete(key)
  return ok
}
function signToken (user) { return jwt.sign({ uid: user.id, plan: user.plan }, JWT_SECRET, { expiresIn: '30d' }) }
async function authOptional (req, _res, next) {
  const a = req.headers.authorization || ''
  const t = a.startsWith('Bearer ') ? a.slice(7) : ''
  if (!t) return next()
  try {
    const p = jwt.verify(t, JWT_SECRET)
    const { rows } = await pool.query('SELECT id,email,phone,plan FROM users WHERE id=$1', [p.uid])
    req.user = rows[0] || null
  } catch { req.user = null } finally { next() }
}

// ---------- Presign (single-file) ----------
app.post('/api/presign', authOptional, async (req, res) => {
  try {
    const user = req.user
    let { filename, contentType, contentLength, plan, durationDays } = req.body || {}
    filename = String(filename || '')
    contentType = String(contentType || 'application/octet-stream')
    contentLength = Number(contentLength || 0)
    plan = String(plan || (user?.plan || 'FREE')).toUpperCase()

    const ttlDays = (plan === 'PRO')
      ? PROCFG.ttlDays
      : (plan === 'PROMAX' ? PMCFG.ttlDays : clamp(num(durationDays || FREECFG.ttlDefaultDays), FREECFG.ttlDefaultDays, FREECFG.ttlMaxDays))

    if (plan === 'FREE' && !user) {
      if (!filename || !contentType || !contentLength) return res.status(400).json({ error: 'bad_params' })
      if (contentLength > FREECFG.sizeCap) return res.status(413).json({ error: 'file_too_large', maxBytes: FREECFG.sizeCap })
      const anon = hashIp(clientIp(req))
      const { rows } = await pool.query(`SELECT COUNT(*)::int AS cnt FROM links WHERE anon_ip=$1 AND created_at>= now()-INTERVAL '30 days'`, [anon])
      if (Number(rows[0]?.cnt || 0) >= FREECFG.maxLinks30d) return res.status(429).json({ error: 'free_link_count_exceeded', limit: FREECFG.maxLinks30d })

      const ext = extOf(filename); const day = new Date().toISOString().slice(0, 10)
      const key = `mt/FREE/${day}/${randomUUID()}${ext ? '.' + ext : ''}`
      await pool.query(`INSERT INTO links (user_id,anon_ip,plan,key,filename,content_type,size_bytes,expires_at,active)
                        VALUES (NULL,$1,'FREE',$2,$3,$4,$5, now()+($6||' days')::interval, true)`,
                        [anon, key, filename, contentType, contentLength, ttlDays])

      const put = new PutObjectCommand({ Bucket: SEALED.S3_BUCKET, Key: key, ContentType: contentType, Metadata: { 'x-plan': 'FREE', 'x-origin': 'mixtli' } })
      const uploadUrl = await getSignedUrl(s3, put, { expiresIn: num(UPLOAD_URL_TTL_SECONDS) })
      const get = new GetObjectCommand({ Bucket: SEALED.S3_BUCKET, Key: key, ResponseContentDisposition: `attachment; filename="${filename}"` })
      const downloadUrl = await getSignedUrl(s3, get, { expiresIn: num(DOWNLOAD_URL_TTL_SECONDS_MAX) })
      return res.json({ key, uploadUrl, uploadHeaders: { 'Content-Type': contentType }, downloadUrl, expiresInSeconds: ttlDays * 24 * 3600 })
    }

    if (!user) return res.status(401).json({ error: 'auth_required' })
    if (plan === 'FREE' && contentLength > FREECFG.sizeCap) return res.status(413).json({ error: 'file_too_large', maxBytes: FREECFG.sizeCap })

    const ext = extOf(filename); const day = new Date().toISOString().slice(0, 10)
    const key = `mt/${plan}/${day}/${randomUUID()}${ext ? '.' + ext : ''}`
    await pool.query(`INSERT INTO links (user_id,plan,key,filename,content_type,size_bytes,expires_at,active)
                      VALUES ($1,$2,$3,$4,$5,$6, now()+($7||' days')::interval, true)`,
                      [user.id, plan, key, filename, contentType, contentLength, ttlDays])

    const put = new PutObjectCommand({ Bucket: SEALED.S3_BUCKET, Key: key, ContentType: contentType, Metadata: { 'x-plan': plan, 'x-origin': 'mixtli' } })
    const uploadUrl = await getSignedUrl(s3, put, { expiresIn: num(UPLOAD_URL_TTL_SECONDS) })
    const get = new GetObjectCommand({ Bucket: SEALED.S3_BUCKET, Key: key, ResponseContentDisposition: `attachment; filename="${filename}"` })
    const downloadUrl = await getSignedUrl(s3, get, { expiresIn: num(DOWNLOAD_URL_TTL_SECONDS_MAX) })
    res.json({ key, uploadUrl, uploadHeaders: { 'Content-Type': contentType }, downloadUrl, expiresInSeconds: ttlDays * 24 * 3600 })
  } catch (e) {
    console.error(e); res.status(500).json({ error: 'presign_failed', detail: String(e) })
  }
})

// ---------- Packages (multi-file link único) ----------
app.post('/api/package/create', authOptional, async (req, res) => {
  try {
    const user = req.user
    const plan = String((req.body?.plan || user?.plan || 'FREE')).toUpperCase()
    const ttlDays = (plan === 'PRO') ? PROCFG.ttlDays : (plan === 'PROMAX' ? PMCFG.ttlDays : clamp(num(req.body?.durationDays || FREECFG.ttlDefaultDays), FREECFG.ttlDefaultDays, FREECFG.ttlMaxDays))
    const id = randomUUID().replace(/-/g, '').slice(0, 12)
    const anon = user ? null : hashIp(clientIp(req))
    const uid = user ? user.id : null

    await pool.query(`INSERT INTO packages (id,user_id,anon_ip,plan,title,expires_at,download_limit)
                      VALUES ($1,$2,$3,$4,$5, now()+($6||' days')::interval, $7)`,
                      [id, uid, anon, plan, req.body?.title || null, ttlDays, null])

    res.json({ ok: true, packageId: id, ttlDays })
  } catch (e) {
    console.error(e); res.status(500).json({ error: 'pkg_create_failed', detail: String(e) })
  }
})

app.post('/api/package/presign', authOptional, async (req, res) => {
  try {
    const { packageId, filename, contentType, contentLength } = req.body || {}
    if (!packageId) return res.status(400).json({ error: 'package_required' })

    const { rows: pk } = await pool.query(`SELECT id, plan FROM packages WHERE id=$1`, [packageId])
    if (pk.length === 0) return res.status(404).json({ error: 'package_not_found' })
    const plan = pk[0].plan
    const size = Number(contentLength || 0)
    if (plan === 'FREE' && size > (num(process.env.FREE_MAX_UPLOAD_MB || '3584') * 1024 * 1024)) {
      return res.status(413).json({ error: 'file_too_large' })
    }

    const ext = extOf(String(filename || '')); const day = new Date().toISOString().slice(0, 10)
    const key = `mt/PKG/${packageId}/${day}/${randomUUID()}${ext ? '.' + ext : ''}`
    await pool.query(`INSERT INTO package_items (package_id,key,filename,content_type,size_bytes)
                      VALUES ($1,$2,$3,$4,$5)`,
                      [packageId, key, filename || 'file', String(contentType || 'application/octet-stream'), size])

    const put = new PutObjectCommand({ Bucket: SEALED.S3_BUCKET, Key: key, ContentType: String(contentType || 'application/octet-stream'), Metadata: { 'x-plan': plan, 'x-origin': 'mixtli', 'x-package': packageId } })
    const uploadUrl = await getSignedUrl(s3, put, { expiresIn: num(UPLOAD_URL_TTL_SECONDS) })
    res.json({ key, uploadUrl, uploadHeaders: { 'Content-Type': String(contentType || 'application/octet-stream') } })
  } catch (e) {
    console.error(e); res.status(500).json({ error: 'pkg_presign_failed', detail: String(e) })
  }
})

app.get('/api/package/meta/:id', async (req, res) => {
  try {
    const id = req.params.id
    const { rows: pkg } = await pool.query(`SELECT id, title, plan, expires_at, downloads, download_limit FROM packages WHERE id=$1`, [id])
    if (pkg.length === 0) return res.status(404).json({ error: 'package_not_found' })
    const { rows: items } = await pool.query(`SELECT id, filename, content_type, size_bytes, downloads FROM package_items WHERE package_id=$1 ORDER BY id ASC`, [id])
    res.json({ id, ...pkg[0], items })
  } catch (e) {
    console.error(e); res.status(500).json({ error: 'pkg_meta_failed' })
  }
})

app.get('/api/dl/:pkg/:itemId', async (req, res) => {
  try {
    const { pkg, itemId } = req.params
    const { rows: pkgRows } = await pool.query(`SELECT id, expires_at, downloads, download_limit FROM packages WHERE id=$1`, [pkg])
    if (pkgRows.length === 0) return res.status(404).send('package_not_found')
    const p = pkgRows[0]
    if (new Date(p.expires_at) < new Date()) return res.status(410).send('expired')
    if (p.download_limit != null && p.downloads >= p.download_limit) return res.status(429).send('download_limit_reached')

    const { rows: itemRows } = await pool.query(`SELECT id, key, filename, downloads FROM package_items WHERE id=$1 AND package_id=$2`, [itemId, pkg])
    if (itemRows.length === 0) return res.status(404).send('item_not_found')
    const it = itemRows[0]

    await pool.query(`UPDATE packages SET downloads=downloads+1 WHERE id=$1`, [pkg])
    await pool.query(`UPDATE package_items SET downloads=downloads+1 WHERE id=$1`, [itemId])

    const get = new GetObjectCommand({ Bucket: SEALED.S3_BUCKET, Key: it.key, ResponseContentDisposition: `attachment; filename="${it.filename}"` })
    const url = await getSignedUrl(s3, get, { expiresIn: num(DOWNLOAD_URL_TTL_SECONDS_MAX) })
    res.redirect(url)
  } catch (e) {
    console.error(e); res.status(500).send('dl_failed')
  }
})

app.get('/dl/:id', async (req, res) => {
  try {
    const id = req.params.id
    const base = (PUBLIC_BASE_URL || '').replace(/\/+$/, '')
    const metaRes = await pool.query(`SELECT id, title, expires_at, downloads, download_limit FROM packages WHERE id=$1`, [id])
    if (metaRes.rows.length === 0) return res.status(404).send('Not found')
    const meta = metaRes.rows[0]
    const itemsRes = await pool.query(`SELECT id, filename, size_bytes FROM package_items WHERE package_id=$1 ORDER BY id ASC`, [id])
    const items = itemsRes.rows
    const left = (meta.download_limit == null) ? '∞' : Math.max(0, meta.download_limit - meta.downloads)
    const ttlText = new Date(meta.expires_at).toISOString()
    const selfUrl = `${base || ''}/dl/${id}`
    const qr = `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(selfUrl)}`
    const human = (n) => { const u = ['B','KB','MB','GB','TB']; let i=0; let x=Number(n||0); while (x>=1024 && i<u.length-1){ x/=1024; i++; } return x.toFixed(i==0?0:1)+' '+u[i] }

    const rows = items.map(it => `<li><a href="/api/dl/${id}/${it.id}">${it.filename}</a> <small>(${human(it.size_bytes)})</small></li>`).join('')

    res.setHeader('Content-Type','text/html; charset=utf-8')
    res.end(`<!doctype html><html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Mixtli · ${id}</title>
<style>:root{color-scheme:dark}body{font-family:system-ui,Segoe UI,Roboto,Arial;background:#0b0b0c;color:#e6e6e6;margin:0}
.container{max-width:760px;margin:24px auto;padding:0 16px}.card{background:#121212;border:1px solid #2b2b2b;border-radius:14px;padding:16px}
.row{display:flex;gap:18px;align-items:center;flex-wrap:wrap}h1{font-size:18px;margin:0 0 4px}small{opacity:.8}
ul{margin:12px 0 0 18px}.pill{font-size:12px;padding:4px 8px;background:#1c1c1c;border:1px solid #333;border-radius:999px}
a{color:#8ec7ff;text-decoration:none}a:hover{text-decoration:underline}</style>
</head><body><div class="container">
<div class="row" style="justify-content:space-between;margin:18px 0">
  <div><h1>Tu paquete está listo</h1>
    <small>ID: ${id} · expira: ${ttlText}</small><br/><small>Descargas restantes: ${left}</small>
  </div>
  <div class="card"><img src="${qr}" alt="QR" width="200" height="200"/></div>
</div>
<div class="card"><b>Archivos</b><ul>${rows||'<li>Vacío</li>'}</ul><p style="margin-top:12px"><a href="${selfUrl}">Copiar link</a></p></div>
</div></body></html>`)
  } catch (e) {
    console.error(e); res.status(500).send('page_failed')
  }
})

// ---------- Boot ----------
await initDb()
const server = app.listen(PORT, () => console.log('MixtliTransfer3000 v2.1.3 on :' + PORT))

// Salida limpia en Render
for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, async () => {
    try { await pool.end() } catch {}
    server.close(() => process.exit(0))
  })
}
