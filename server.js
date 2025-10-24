
// MixtliTransfer3000 — Server (PROD sealed non-secrets)
// - Hardcodes: S3_ENDPOINT, S3_BUCKET, S3_REGION, S3_FORCE_PATH_STYLE, ALLOWED_ORIGINS
// - Secrets & DB still come from env: S3_ACCESS_KEY_ID, S3_SECRET_ACCESS_KEY, DATABASE_URL, JWT_SECRET
// - Plans: read from env (with sensible defaults)

import 'dotenv/config'
import express from 'express'
import cors from 'cors'
import { randomUUID } from 'crypto'
import jwt from 'jsonwebtoken'
import pg from 'pg'
import { S3Client, PutObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3'
import { getSignedUrl } from '@aws-sdk/s3-request-presigner'

// ----------- SEALED VALUES (edit here if you change domain/bucket) -----------
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
// -----------------------------------------------------------------------------

const {
  PORT = 10000,

  // Secrets still come from env
  S3_ACCESS_KEY_ID,
  S3_SECRET_ACCESS_KEY,
  DATABASE_URL,
  JWT_SECRET = 'change_me',
  OTP_TTL_MIN = '10',

  // Plan envs
  FREE_MAX_UPLOAD_MB = '3584',
  FREE_LINK_TTL_DEFAULT_DAYS = '3',
  FREE_LINK_TTL_MAX_DAYS = '30',
  FREE_MAX_LINKS_PER_30D = '10',

  PRO_MAX_PERIOD_GB = '400',
  PRO_PERIOD_DAYS = '30',
  PRO_LINK_TTL_DAYS = '7',
  PRO_MAX_UPLOAD_MB = '',

  PROMAX_PERIOD_DAYS = '30',
  PROMAX_LINK_TTL_DAYS = '22',
  PROMAX_MAX_UPLOAD_MB = '',

  UPLOAD_URL_TTL_SECONDS = '3600',
  DOWNLOAD_URL_TTL_SECONDS_MAX = '86400'
} = process.env

if (!SEALED.S3_ENDPOINT || !SEALED.S3_BUCKET || !S3_ACCESS_KEY_ID || !S3_SECRET_ACCESS_KEY) {
  console.error('[FATAL] Missing R2 credentials or sealed config'); process.exit(1)
}
if (!DATABASE_URL) {
  console.error('[FATAL] Missing DATABASE_URL'); process.exit(1)
}

const MB = 1024*1024

const FREE = {
  sizeCap: toNum(FREE_MAX_UPLOAD_MB)*MB,
  ttlDefaultDays: toNum(FREE_LINK_TTL_DEFAULT_DAYS),
  ttlMaxDays: toNum(FREE_LINK_TTL_MAX_DAYS),
  maxLinks30d: toNum(FREE_MAX_LINKS_PER_30D)
}
const PRO = {
  periodDays: toNum(PRO_PERIOD_DAYS),
  capBytesPerPeriod: toNum(PRO_MAX_PERIOD_GB)*1024*1024*1024,
  ttlDays: toNum(PRO_LINK_TTL_DAYS),
  sizeCap: PRO_MAX_UPLOAD_MB ? toNum(PRO_MAX_UPLOAD_MB)*MB : Infinity
}
const PROMAX = {
  periodDays: toNum(PROMAX_PERIOD_DAYS),
  ttlDays: toNum(PROMAX_LINK_TTL_DAYS),
  sizeCap: PROMAX_MAX_UPLOAD_MB ? toNum(PROMAX_MAX_UPLOAD_MB)*MB : Infinity
}

const s3 = new S3Client({
  region: SEALED.S3_REGION,
  endpoint: SEALED.S3_ENDPOINT,
  credentials: { accessKeyId: S3_ACCESS_KEY_ID, secretAccessKey: S3_SECRET_ACCESS_KEY },
  forcePathStyle: !!SEALED.S3_FORCE_PATH_STYLE
})

const pool = new pg.Pool({ connectionString: DATABASE_URL })

const app = express()
app.use(cors({
  origin: (origin, cb)=>{
    if (!origin) return cb(null, true)
    if (SEALED.ALLOWED_ORIGINS.includes(origin)) return cb(null, true)
    cb(new Error('origin_not_allowed'))
  },
  methods: ['GET','POST','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization','x-mixtli-token']
}))
app.use(express.json({ limit: '1mb' }))

app.get('/api/health', (_req,res)=>{
  res.json({ ok:true, service:'mixtlitransfer3000', time:new Date().toISOString() })
})

// ===== OTP (in-memory) =====
const otpStore = new Map()
function setOtp(key){
  const code = String(Math.floor(100000 + Math.random()*900000))
  const exp = Date.now() + toNum(OTP_TTL_MIN)*60*1000
  otpStore.set(key, { code, exp })
  console.log('[OTP]', key, code) // replace with email/SMS in prod
}
function verifyOtp(key, code){
  const row = otpStore.get(key); if(!row) return false
  if (Date.now() > row.exp) { otpStore.delete(key); return false }
  const ok = row.code === String(code); if (ok) otpStore.delete(key); return ok
}

// ===== AUTH =====
function signToken(user){ return jwt.sign({ uid:user.id, plan:user.plan }, JWT_SECRET, { expiresIn:'30d' }) }
async function authOptional(req,_res,next){
  const auth = req.headers.authorization || ''
  const token = auth.startsWith('Bearer ')? auth.slice(7): ''
  if(!token) return next()
  try{
    const payload = jwt.verify(token, JWT_SECRET)
    const { rows } = await pool.query('SELECT id,email,phone,plan FROM users WHERE id=$1',[payload.uid])
    req.user = rows[0] || null
  }catch(_e){ req.user=null } finally { next() }
}
async function authRequired(req,res,next){
  await authOptional(req,res,()=>{})
  if(!req.user) return res.status(401).json({ error:'auth_required' })
  next()
}

// ===== HELPERS =====
function toNum(x){ return Math.max(0, parseInt(String(x||'0'),10) || 0) }
function extOf(filename=''){ const i=filename.lastIndexOf('.'); return i>-1? filename.slice(i+1).toLowerCase(): '' }
function clamp(n,a,b){ return Math.max(a, Math.min(b,n)) }

// ===== AUTH ROUTES =====
app.post('/api/auth/register', async (req,res)=>{
  const { email, phone } = req.body || {}
  const idKey = (email && String(email).toLowerCase()) || (phone && String(phone)) || ''
  if(!idKey) return res.status(400).json({ error:'email_or_phone_required' })
  setOtp(idKey)
  res.json({ ok:true, msg:'otp_sent' })
})

app.post('/api/auth/verify-otp', async (req,res)=>{
  const { email, phone, otp } = req.body || {}
  const idKey = (email && String(email).toLowerCase()) || (phone && String(phone)) || ''
  if(!idKey || !otp) return res.status(400).json({ error:'need_id_and_otp' })
  if(!verifyOtp(idKey, otp)) return res.status(400).json({ error:'otp_invalid' })

  const client = await pool.connect()
  try{
    await client.query('BEGIN')
    let row
    if(email){
      const r = await client.query(
        `INSERT INTO users (email, plan) VALUES ($1,'FREE')
         ON CONFLICT (email) DO UPDATE SET updated_at=now()
         RETURNING id,email,phone,plan`,
        [email.toLowerCase()]
      )
      row = r.rows[0]
    }else{
      const r = await client.query(
        `INSERT INTO users (phone, plan) VALUES ($1,'FREE')
         ON CONFLICT (phone) DO UPDATE SET updated_at=now()
         RETURNING id,email,phone,plan`,
        [phone]
      )
      row = r.rows[0]
    }
    await client.query('COMMIT')
    const token = signToken(row)
    res.json({ token, user: row })
  }catch(e){
    await client.query('ROLLBACK'); console.error(e); res.status(500).json({ error:'verify_failed' })
  }finally{ client.release() }
})

app.get('/api/me', authRequired, async (req,res)=>{
  const user = req.user
  const { rows: u } = await pool.query(
    `SELECT COALESCE(SUM(size_bytes),0) AS bytes, COUNT(*) AS count
     FROM links WHERE user_id=$1 AND created_at >= now() - INTERVAL '30 days'`, [user.id]
  )
  const usage = { bytes:Number(u[0].bytes||0), count:Number(u[0].count||0) }
  const { rows: links } = await pool.query(
    `SELECT id,key,filename,size_bytes,expires_at
     FROM links WHERE user_id=$1 ORDER BY created_at DESC LIMIT 15`, [user.id]
  )
  const items = await Promise.all(links.map(async l=>{
    const getCmd = new GetObjectCommand({ Bucket:SEALED.S3_BUCKET, Key:l.key, ResponseContentDisposition:`attachment; filename="${l.filename||'file'}"` })
    const downloadUrl = await getSignedUrl(s3, getCmd, { expiresIn: toNum(DOWNLOAD_URL_TTL_SECONDS_MAX) })
    return { ...l, downloadUrl }
  }))
  res.json({ user, usage, links: items })
})

// ===== PLAN LIMITS =====
function planLimits(plan, durationDays){
  if(plan==='FREE'){
    const ttl = clamp(toNum(durationDays || FREE.ttlDefaultDays), FREE.ttlDefaultDays, FREE.ttlMaxDays)
    return { sizeCap: FREE.sizeCap, ttlDays: ttl, periodDays: 30, capBytesPerPeriod: 0, maxLinks30d: FREE.maxLinks30d }
  }
  if(plan==='PRO'){
    return { sizeCap: PRO.sizeCap, ttlDays: PRO.ttlDays, periodDays: PRO.periodDays, capBytesPerPeriod: PRO.capBytesPerPeriod, maxLinks30d: Infinity }
  }
  if(plan==='PROMAX'){
    return { sizeCap: PROMAX.sizeCap, ttlDays: PROMAX.ttlDays, periodDays: PROMAX.periodDays, capBytesPerPeriod: Infinity, maxLinks30d: Infinity }
  }
  throw new Error('unknown_plan')
}

// ===== PRESIGN =====
app.post('/api/presign', authRequired, async (req,res)=>{
  try{
    const user = req.user
    let { filename, contentType, contentLength, plan, durationDays } = req.body || {}
    filename = String(filename||''); contentType = String(contentType||'application/octet-stream')
    contentLength = Number(contentLength||0); plan = String(plan || user.plan || 'FREE').toUpperCase()

    const lim = planLimits(plan, durationDays)
    if(!filename || !contentType || !contentLength) return res.status(400).json({ error:'bad_params' })
    if(Number.isFinite(lim.sizeCap) && contentLength > lim.sizeCap) return res.status(413).json({ error:'file_too_large', maxBytes: lim.sizeCap })

    const { rows: agg } = await pool.query(
      `SELECT COALESCE(SUM(size_bytes),0) AS sum_bytes, COUNT(*) AS cnt
       FROM links WHERE user_id=$1 AND created_at >= now() - INTERVAL '30 days'`, [user.id]
    )
    const usedBytes = Number(agg[0].sum_bytes||0); const usedCount = Number(agg[0].cnt||0)

    if(plan==='FREE'){
      if(usedCount >= lim.maxLinks30d) return res.status(429).json({ error:'free_link_count_exceeded', limit: lim.maxLinks30d })
    } else if(plan==='PRO'){
      if(usedBytes + contentLength > lim.capBytesPerPeriod) return res.status(429).json({ error:'pro_bytes_quota_exceeded', limitBytes: lim.capBytesPerPeriod, usedBytes })
    }

    const ext = extOf(filename); const day = new Date().toISOString().slice(0,10)
    const key = `mt/${plan}/${day}/${randomUUID()}${ext?'.'+ext:''}`

    const client = await pool.connect()
    try{
      await client.query('BEGIN')
      await client.query(
        `INSERT INTO links (user_id, plan, key, filename, content_type, size_bytes, expires_at, active)
         VALUES ($1,$2,$3,$4,$5,$6, now() + ($7 || ' days')::interval, true)`,
        [user.id, plan, key, filename, contentType, contentLength, lim.ttlDays]
      )
      await client.query('COMMIT')
    }catch(e){ await client.query('ROLLBACK'); throw e } finally { client.release() }

    const putCmd = new PutObjectCommand({ Bucket:SEALED.S3_BUCKET, Key:key, ContentType:contentType, Metadata:{ 'x-plan': plan, 'x-origin':'mixtli' } })
    const uploadUrl = await getSignedUrl(s3, putCmd, { expiresIn: toNum(UPLOAD_URL_TTL_SECONDS) })
    const getCmd = new GetObjectCommand({ Bucket:SEALED.S3_BUCKET, Key:key, ResponseContentDisposition:`attachment; filename="${filename}"` })
    const downloadUrl = await getSignedUrl(s3, getCmd, { expiresIn: toNum(DOWNLOAD_URL_TTL_SECONDS_MAX) })

    res.json({ key, uploadUrl, uploadHeaders:{ 'Content-Type': contentType }, downloadUrl, expiresInSeconds: lim.ttlDays*24*3600 })
  }catch(e){ console.error(e); res.status(500).json({ error:'presign_failed', detail:String(e) }) }
})

app.get('/', (_req,res)=>res.send('MixtliTransfer3000 API OK'))

app.listen(PORT, ()=> console.log('MixtliTransfer3000 listening on :'+PORT))
