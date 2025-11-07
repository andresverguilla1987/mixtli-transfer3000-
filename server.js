/* Mixtli Transfer — Backend v2.15.2-MAX (UNIFIED, with Plans, FIXED) */
import 'dotenv/config'
import express from 'express'
import cors from 'cors'
import jwt from 'jsonwebtoken'
import pg from 'pg'
import nodemailer from 'nodemailer'
import twilio from 'twilio'
import rateLimit from 'express-rate-limit'
import crypto from 'crypto'
import { S3Client, PutObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3'
import { getSignedUrl } from '@aws-sdk/s3-request-presigner'
import archiver from 'archiver'
import { Readable } from 'node:stream'
import { scryptSync, randomBytes, timingSafeEqual } from 'node:crypto'

if (!globalThis.fetch) {
  const { default: nodeFetch } = await import('node-fetch')
  globalThis.fetch = nodeFetch
}

const EXPECTED = {
  NODE_ENV: ['production'],
  JWT_SECRET: 'present',
  DATABASE_URL: 'present',
  S3_ENDPOINT: 'present',
  S3_BUCKET: 'present',
  S3_ACCESS_KEY_ID: 'present',
  S3_SECRET_ACCESS_KEY: 'present',
  S3_FORCE_PATH_STYLE: ['true'],
  ALLOWED_ORIGINS: 'json-array-nonempty',
  BACKEND_PUBLIC_ORIGIN: 'present'
}
function assertEnv () {
  const errs = []
  for (const [k, rule] of Object.entries(EXPECTED)) {
    const v = process.env[k]
    if (rule === 'present') { if (!v) errs.push(`${k} vacío`); continue }
    if (rule === 'json-array-nonempty') {
      try {
        const arr = JSON.parse(v || '[]')
        if (!Array.isArray(arr) || arr.length === 0) errs.push(`${k} debe ser JSON array no vacío`)
      } catch { errs.push(`${k} JSON inválido`) }
      continue
    }
    if (Array.isArray(rule)) {
      if (!rule.includes(String(v))) errs.push(`${k}=${v} no permitido (esperado: ${rule.join('|')})`)
      continue
    }
  }
  if (errs.length) { console.error('[CONFIG_GUARD] ❌', errs); process.exit(1) }
  console.log('[CONFIG_GUARD] ✅ Config OK')
}
assertEnv()

const {
  PORT = 10000,
  DATABASE_URL,
  JWT_SECRET = 'change_me',
  OTP_TTL_MIN = '10',

  SENDGRID_API_KEY,
  SENDGRID_FROM,
  SMTP_HOST,
  SMTP_PORT = '587',
  SMTP_USER,
  SMTP_PASS,
  SMTP_FROM,

  ALLOWED_ORIGINS,

  TWILIO_ACCOUNT_SID,
  TWILIO_AUTH_TOKEN,
  TWILIO_FROM,

  S3_ENDPOINT,
  S3_BUCKET,
  S3_REGION = 'auto',
  S3_ACCESS_KEY_ID,
  S3_SECRET_ACCESS_KEY,
  S3_FORCE_PATH_STYLE,

  PUBLIC_BASE_URL,
  FORCE_RELATIVE_URLS = 'true',
  CONTENT_DISPOSITION = '',
  CONFIG_DIAG_TOKEN = '',
  BACKEND_PUBLIC_ORIGIN,

  FREE_MAX_TOTAL_MB = '200',
  FREE_MAX_DOWNLOADS = '50',
  PRO_MAX_TOTAL_MB = '20480',
  PRO_MAX_DOWNLOADS = '1000',
  PROMAX_MAX_TOTAL_MB = '102400',
  PROMAX_MAX_DOWNLOADS = '2000',

  PACKAGE_PASSWORD_MINLEN = '4',
  DL_RATE_WINDOW_S = '60',
  DL_RATE_MAX = '60',
  ALLOW_DEMO_OTP = 'false'
} = process.env

const pool = new pg.Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } })
async function safeExec (sql) { try { await pool.query(sql) } catch (e) { console.warn('[safeExec]', e.message) } }
async function initDb () {
  await safeExec('CREATE EXTENSION IF NOT EXISTS "pgcrypto";')
  await safeExec('CREATE EXTENSION IF NOT EXISTS "uuid-ossp";')
  await safeExec(`CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT, phone TEXT, plan TEXT NOT NULL DEFAULT 'FREE',
    plan_expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
  );`)
  await safeExec(`CREATE TABLE IF NOT EXISTS otps (
    id BIGSERIAL PRIMARY KEY,
    key TEXT NOT NULL, code TEXT NOT NULL, exp TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  );`)
  await safeExec(`DO $$
  BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname='users_email_key') THEN
      EXECUTE 'CREATE UNIQUE INDEX users_email_key ON users(email) WHERE email IS NOT NULL';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname='users_phone_key') THEN
      EXECUTE 'CREATE UNIQUE INDEX users_phone_key ON users(phone) WHERE phone IS NOT NULL';
    END IF;
  END $$;`)
  await safeExec(`CREATE TABLE IF NOT EXISTS packages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_uid UUID, title TEXT, total_size BIGINT DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ
  );`)
  await safeExec(`CREATE TABLE IF NOT EXISTS package_files (
    id BIGSERIAL PRIMARY KEY,
    package_id UUID REFERENCES packages(id) ON DELETE CASCADE,
    key TEXT NOT NULL, filename TEXT, size BIGINT, content_type TEXT
  );`)
  await safeExec('ALTER TABLE packages ADD COLUMN IF NOT EXISTS password_hash TEXT;')
  await safeExec('ALTER TABLE packages ADD COLUMN IF NOT EXISTS password_salt TEXT;')
  await safeExec('ALTER TABLE packages ADD COLUMN IF NOT EXISTS download_count BIGINT NOT NULL DEFAULT 0;')
  await safeExec('ALTER TABLE packages ADD COLUMN IF NOT EXISTS max_downloads BIGINT;')
  await safeExec('ALTER TABLE packages ADD COLUMN IF NOT EXISTS max_total_mb BIGINT;')
  await safeExec('CREATE TABLE IF NOT EXISTS package_downloads (id BIGSERIAL PRIMARY KEY, package_id UUID REFERENCES packages(id) ON DELETE CASCADE, ip INET, user_agent TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT now());')
  await safeExec('CREATE INDEX IF NOT EXISTS pkg_dl_pkg_idx ON package_downloads(package_id);')
  await safeExec('CREATE INDEX IF NOT EXISTS package_files_pkg_idx ON package_files(package_id);')
  await safeExec('CREATE INDEX IF NOT EXISTS packages_expires_idx ON packages(expires_at);')
  console.log('[DB] ready')
}

const ttlMin = parseInt(OTP_TTL_MIN || '10', 10)

function rand6 () { return String(Math.floor(100000 + Math.random() * 900000)) }
function normalizePhone (p) {
  if (!p) return ''
  let s = String(p).trim().replace(/[()\s-]/g, '')
  if (s.toLowerCase().startsWith('whatsapp:')) s = s.slice('whatsapp:'.length)
  if (!s.startsWith('+') && /^\d{10,15}$/.test(s)) s = '+' + s
  return s
}
function normalizeId (email, phone) {
  const em = (email || '').trim().toLowerCase()
  const ph = normalizePhone(phone || '')
  return em || ph
}
function safeName (name='') {
  return String(name).normalize('NFKD')
    .replace(/[\u0300-\u036f]/g,'')
    .replace(/[^A-Za-z0-9._-]+/g,'_')
    .slice(0,180)
}
function sanitizeEndpoint (ep) { return String(ep || '').replace(/\/+$/,'') }
function sanitizeOrigin  (o)  { return String(o  || '').replace(/\/+$/,'') }
const BACKEND_ORIGIN = sanitizeOrigin(process.env.BACKEND_PUBLIC_ORIGIN)

function hashPassword(pwd){ const salt = randomBytes(16).toString('hex'); const hash = scryptSync(String(pwd), salt, 32).toString('hex'); return { salt, hash } }
function verifyPassword(pwd, salt, goodHash){
  if (!salt || !goodHash) return false
  const h = scryptSync(String(pwd), salt, 32).toString('hex')
  try { return timingSafeEqual(Buffer.from(h,'hex'), Buffer.from(goodHash,'hex')) } catch { return false }
}
async function createOtp (key) {
  const code = rand6()
  await pool.query(
    `INSERT INTO otps (key, code, exp)
     VALUES ($1,$2, now() + ($3 || ' minutes')::interval)`,
    [key, code, ttlMin]
  )
  return code
}
async function verifyOtpDb (key, code) {
  const q = await pool.query(
    `SELECT id, code, exp FROM otps
     WHERE key=$1 ORDER BY id DESC LIMIT 1`, [key])
  if (!q.rows.length) return false
  const row = q.rows[0]
  if (row.code !== String(code)) return false
  if (new Date(row.exp) < new Date()) return false
  await pool.query(`DELETE FROM otps WHERE id=$1`, [row.id])
  return true
}
function signToken (user) { return jwt.sign({ uid: user.id, plan: user.plan }, process.env.JWT_SECRET, { expiresIn: '30d' }) }
function authUid (req){
  try {
    const h = req.headers.authorization || ''
    const tok = h.startsWith('Bearer ') ? h.slice(7) : ''
    if (!tok) return null
    const dec = jwt.verify(tok, process.env.JWT_SECRET)
    return dec?.uid || null
  } catch { return null }
}
function requireAuth (req,res,next){ const uid = authUid(req); if (!uid) return res.status(401).json({ error:'no_token' }); req.uid = uid; next() }

const app = express()
let ORIGINS = []
try { ORIGINS = JSON.parse(process.env.ALLOWED_ORIGINS || '[]') } catch {}
function isNetlifyPreview (origin){ try { return /\.netlify\.app$/i.test(new URL(origin).hostname) } catch { return false } }
const corsMw = cors({
  origin: (o, cb) => { if (!o) return cb(null, true); if (ORIGINS.includes(o) || isNetlifyPreview(o)) return cb(null, true); return cb(new Error('origin_not_allowed')) },
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization','x-admin-token','x-cron-token','x-mixtli-token','x-package-password','x-config-token'],
  optionsSuccessStatus: 204
})
app.use((req,res,next)=>corsMw(req,res,(err)=>{ if (err?.message==='origin_not_allowed') return res.status(403).json({ error:'origin_not_allowed', origin:req.headers.origin||null }); next() }))
app.options('*', corsMw)
app.set('trust proxy', 1)
app.use(express.json({ limit:'4mb' }))

const otpLimiter = rateLimit({ windowMs: 5*60*1000, max: 8, standardHeaders:true, legacyHeaders:false, skip:(req)=>req.method==='OPTIONS' })

app.get('/', (_req,res)=>res.type('text/plain').send('OK'))
app.get('/api/health', (_req,res)=>res.json({ ok:true, time:new Date().toISOString(), ver:'2.15.2-MAX', channel:'unified' }))

async function handleRegister(req, res) {
  try {
    const { email='', phone='' } = req.body || {}
    const id = normalizeId(email, phone)
    if (!id) return res.status(400).json({ error:'email_or_phone_required' })

    const code = await createOtp(id)

    if (email) {
      const smtpPortN = parseInt(process.env.SMTP_PORT || '587', 10)
      if (process.env.SENDGRID_API_KEY && process.env.SENDGRID_FROM) {
        const body = {
          personalizations: [{ to: [{ email: email.trim().toLowerCase() }] }],
          from: { email: process.env.SENDGRID_FROM },
          subject: 'Tu código Mixtli',
          content: [{ type: 'text/plain', value: `Tu código es: ${code}\nExpira en ${ttlMin} minutos.` }]
        }
        const r = await fetch('https://api.sendgrid.com/v3/mail/send', {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${process.env.SENDGRID_API_KEY}`, 'Content-Type': 'application/json' },
          body: JSON.stringify(body)
        })
        if (!r.ok) throw new Error('sendgrid_failed')
      } else if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
        const transport = nodemailer.createTransport({
          host: process.env.SMTP_HOST, port: smtpPortN, secure: smtpPortN===465,
          auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
        })
        await transport.sendMail({ from: process.env.SMTP_FROM || process.env.SMTP_USER, to: email, subject: 'Tu código Mixtli', text: `Tu código es: ${code}\nExpira en ${ttlMin} minutos.` })
      } else {
        throw new Error('mail_channel_not_configured')
      }
    } else {
      if (!(process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN && process.env.TWILIO_FROM))
        throw new Error('twilio_not_configured')
      const twilioClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN)
      const to = normalizePhone(phone)
      await twilioClient.messages.create({ to, from: process.env.TWILIO_FROM, body: `Mixtli: tu código es ${code}. Expira en ${ttlMin} min.` })
    }

    return res.json({ ok:true, msg:'otp_sent' })
  } catch (e) {
    console.error('[otp_send_failed]', e?.message || e)
    return res.status(500).json({ error:'otp_send_failed', detail:String(e?.message||e) })
  }
}
async function handleVerify(req, res) {
  try{
    const { email='', phone='', otp } = req.body || {}
    const id = normalizeId(email, phone)
    if (!id || !otp) return res.status(400).json({ error:'need_id_and_otp' })

    const ok = await verifyOtpDb(id, otp)
    if (!ok) return res.status(400).json({ error:'otp_invalid' })

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
  } catch (e) { console.error('[verify_failed]', e); res.status(500).json({ error:'verify_failed' }) }
}

app.post(['/api/auth/register','/auth/register'], otpLimiter, handleRegister)
app.post(['/api/auth/verify-otp','/auth/verify-otp','/auth/verify'], handleVerify)

const PLAN_ORDER = ['FREE','PRO','PROMAX']
const planCatalog = {
  FREE:   { label:'Free',    maxFileMB:Number(process.env.FREE_MAX_TOTAL_MB||200),   maxDownloads:Number(process.env.FREE_MAX_DOWNLOADS||50),   ttlDaysDefault:3,  ttlDaysOptions:[3,7,22,30] },
  PRO:    { label:'Pro',     maxFileMB:Number(process.env.PRO_MAX_TOTAL_MB||20480),  maxDownloads:Number(process.env.PRO_MAX_DOWNLOADS||1000), ttlDaysDefault:7,  ttlDaysOptions:[3,7,22,30] },
  PROMAX: { label:'Pro Max', maxFileMB:Number(process.env.PROMAX_MAX_TOTAL_MB||102400), maxDownloads:Number(process.env.PROMAX_MAX_DOWNLOADS||2000), ttlDaysDefault:22, ttlDaysOptions:[3,7,22,30] }
}
function limitTextByPlan (plan){ const p = planCatalog[plan] || planCatalog.FREE; return `Límites (${p.label}): Archivo máx ${p.maxFileMB} MB · Descargas máx ${p.maxDownloads} · TTL por defecto ${p.ttlDaysDefault} días` }
function planLimits (plan='FREE'){
  const p = String(plan||'FREE').toUpperCase()
  if (p === 'PRO')    return { maxTotalMB:Number(process.env.PRO_MAX_TOTAL_MB||20480),    maxDownloads:Number(process.env.PRO_MAX_DOWNLOADS||1000) }
  if (p === 'PROMAX') return { maxTotalMB:Number(process.env.PROMAX_MAX_TOTAL_MB||102400), maxDownloads:Number(process.env.PROMAX_MAX_DOWNLOADS||2000) }
  return { maxTotalMB:Number(process.env.FREE_MAX_TOTAL_MB||200), maxDownloads:Number(process.env.FREE_MAX_DOWNLOADS||50) }
}

app.get('/api/plan', (req,res,next)=>requireAuth(req,res,next), async (req,res)=>{
  try {
    const row = (await pool.query('SELECT plan FROM users WHERE id=$1',[req.uid])).rows[0]
    const current = (row?.plan || 'FREE').toUpperCase()
    const info = planCatalog[current] || planCatalog.FREE
    res.json({ plan: current, info, limits_text: limitTextByPlan(current) })
  } catch(e){ console.error('[plan:get]', e); res.status(500).json({ error:'plan_get_failed' }) }
})
app.post('/api/plan/upgrade', (req,res,next)=>requireAuth(req,res,next), async (req,res)=>{
  try {
    const { plan } = req.body || {}
    const target = String(plan || '').toUpperCase()
    if (!planCatalog[target]) return res.status(400).json({ error:'invalid_plan' })

    const r = await pool.query('SELECT plan FROM users WHERE id=$1',[req.uid])
    const current = (r.rows[0]?.plan || 'FREE').toUpperCase()
    if (PLAN_ORDER.indexOf(target) <= PLAN_ORDER.indexOf(current)) {
      return res.status(400).json({ error:`already_${current.toLowerCase()}_or_higher` })
    }
    await pool.query('UPDATE users SET plan=$1, updated_at=now() WHERE id=$2',[target, req.uid])
    res.json({ ok:true, message:`Upgraded to ${target}`, plan: target, limits_text: limitTextByPlan(target) })
  } catch(e){ console.error('[plan:upgrade]', e); res.status(500).json({ error:'plan_upgrade_failed' }) }
})
app.post('/api/plan/downgrade', (req,res,next)=>requireAuth(req,res,next), async (req,res)=>{
  try {
    await pool.query('UPDATE users SET plan=$1, updated_at=now() WHERE id=$2',['FREE', req.uid])
    res.json({ ok:true, message:'Downgraded to FREE', plan:'FREE', limits_text: limitTextByPlan('FREE') })
  } catch(e){ console.error('[plan:downgrade]', e); res.status(500).json({ error:'plan_downgrade_failed' }) }
})

const s3 = (process.env.S3_ENDPOINT && process.env.S3_BUCKET && process.env.S3_ACCESS_KEY_ID && process.env.S3_SECRET_ACCESS_KEY)
  ? new S3Client({
      region: process.env.S3_REGION || 'auto',
      endpoint: process.env.S3_ENDPOINT,
      credentials: { accessKeyId: process.env.S3_ACCESS_KEY_ID, secretAccessKey: process.env.S3_SECRET_ACCESS_KEY },
      forcePathStyle: String(process.env.S3_FORCE_PATH_STYLE).toLowerCase() === 'true'
    })
  : null

async function buildPublicUrl (key){
  if (process.env.PUBLIC_BASE_URL) return `${sanitizeEndpoint(process.env.PUBLIC_BASE_URL)}/${key}`
  const endpoint = sanitizeEndpoint(process.env.S3_ENDPOINT)
  const host = endpoint.replace(/^https?:\/\//,'')
  const force = String(process.env.S3_FORCE_PATH_STYLE).toLowerCase() === 'true'
  return force ? `${endpoint}/${process.env.S3_BUCKET}/${key}` : `https://${process.env.S3_BUCKET}.${host}/${key}`
}
function absoluteZipUrl (id){ return `${BACKEND_ORIGIN}/api/pack/${id}/zip` }
function asNodeStream (body){
  if (!body) return null
  if (typeof Readable.fromWeb === 'function' && body?.getReader) {
    try { return Readable.fromWeb(body) } catch {}
  }
  return body
}

app.post('/api/presign', (req,res,next)=>requireAuth(req,res,next), async (req,res)=>{
  try{
    if (!s3) return res.status(500).json({ error:'s3_not_configured' })
    const { filename, type='application/octet-stream' } = req.body || {}
    const base = safeName(filename || `file-${Date.now()}`)
    const key  = `uploads/${new Date().toISOString().slice(0,10)}/${crypto.randomUUID()}-${base}`
    const params = { Bucket:process.env.S3_BUCKET, Key:key, ContentType:type }
    if (process.env.CONTENT_DISPOSITION) params.ContentDisposition = process.env.CONTENT_DISPOSITION
    const cmd = new PutObjectCommand(params)
    const url = await getSignedUrl(s3, cmd, { expiresIn:300 })
    res.json({ method:'PUT', url, key, publicUrl: await buildPublicUrl(key) })
  } catch (e) { console.error('[presign_failed]', e); res.status(500).json({ error:'presign_failed', detail:String(e?.message||e) }) }
})
app.post('/api/complete', (req,res,next)=>requireAuth(req,res,next), async (req,res)=>{
  try{
    const { key } = req.body || {}
    if (!key) return res.status(400).json({ error:'key_required' })
    res.json({ ok:true, publicUrl: await buildPublicUrl(key) })
  } catch(e){ console.error('[complete_failed]', e); res.status(500).json({ error:'complete_failed' }) }
})

app.post('/api/pack/create', (req,res,next)=>requireAuth(req,res,next), async (req,res)=>{
  try{
    const { title='Mis archivos', ttlDays=30, files=[], password='', maxDownloads, maxTotalMB } = req.body || {}
    if (!Array.isArray(files) || files.length===0) return res.status(400).json({ error:'no_files' })

    const userRow = (await pool.query('SELECT id, plan FROM users WHERE id=$1',[req.uid])).rows[0]
    const lim = planLimits(userRow?.plan || 'FREE')

    const totalSize = files.reduce((a,f)=> a + (Number(f.size)||0), 0)
    const totalMB   = Math.ceil(totalSize/1048576)
    const effectiveMaxMB = Math.min(Number(maxTotalMB || lim.maxTotalMB), lim.maxTotalMB)
    if (totalMB > effectiveMaxMB) return res.status(400).json({ error:'package_too_big', max_mb:effectiveMaxMB, got_mb:totalMB })

    const ttl = Math.min(Math.max(parseInt(ttlDays||30,10),1),180)

    let password_hash=null, password_salt=null
    const minLen = parseInt(process.env.PACKAGE_PASSWORD_MINLEN || '4', 10)
    if (password) {
      if (String(password).length < minLen) return res.status(400).json({ error:'weak_password', min:minLen })
      const h = hashPassword(password); password_hash=h.hash; password_salt=h.salt
    }

    let effMaxDownloads = null
    if (maxDownloads != null) {
      const cap = lim.maxDownloads
      effMaxDownloads = Math.min(Number(maxDownloads||0), cap)
      if (effMaxDownloads <= 0) effMaxDownloads = null
    }

    const r = await pool.query(
      `INSERT INTO packages (owner_uid, title, total_size, expires_at, password_hash, password_salt, max_downloads, max_total_mb)
       VALUES ($1,$2,$3, now() + ($4 || ' days')::interval, $5,$6,$7,$8)
       RETURNING id, expires_at`,
      [req.uid, title, totalSize, ttl, password_hash, password_salt, effMaxDownloads, effectiveMaxMB]
    )
    const pid = r.rows[0].id

    const params = []
    const vals = []
    for (const f of files) {
      params.push(pid, f.key, f.name || null, Number(f.size)||0, f.type || null)
      const base = params.length - 4
      vals.push(`($${base},$${base+1},$${base+2},$${base+3},$${base+4})`)
    }
    await pool.query(
      `INSERT INTO package_files (package_id, key, filename, size, content_type)
       VALUES ${vals.join(',')}`,
      params
    )

    const sharePath = `/share/${pid}`
    const relative = String(process.env.FORCE_RELATIVE_URLS || 'true').toLowerCase() === 'true'
    const url = relative ? sharePath : ((process.env.PUBLIC_BASE_URL||'') ? (sanitizeEndpoint(process.env.PUBLIC_BASE_URL)+sharePath) : sharePath)

    res.json({ ok:true, id:pid, url, expires_at:r.rows[0].expires_at, password:!!password })
  } catch (e) { console.error('[pack_create_failed]', e); res.status(500).json({ error:'pack_create_failed' }) }
})

app.get('/api/pack/:id', async (req,res)=>{
  try{
    const id = req.params.id
    const p = await pool.query('SELECT * FROM packages WHERE id=$1',[id])
    if (!p.rows.length) return res.status(404).json({ error:'not_found' })
    const f = await pool.query(
      `SELECT key, filename, size, content_type FROM package_files
       WHERE package_id=$1 ORDER BY id`, [id]
    )
    const files = await Promise.all(f.rows.map(async r => ({
      name: r.filename || 'file',
      size: Number(r.size) || 0,
      type: r.content_type,
      url: await buildPublicUrl(r.key)
    })))
    res.json({
      id, title:p.rows[0].title, total_size:Number(p.rows[0].total_size)||0,
      expires_at:p.rows[0].expires_at, files, zip_url: absoluteZipUrl(id)
    })
  } catch (e) { console.error('[pack_fetch_failed]', e); res.status(500).json({ error:'pack_fetch_failed' }) }
})

function absoluteZipUrl (id){ return `${BACKEND_ORIGIN}/api/pack/${id}/zip` }
function asNodeStream (body){
  if (!body) return null
  if (typeof Readable.fromWeb === 'function' && body?.getReader) {
    try { return Readable.fromWeb(body) } catch {}
  }
  return body
}

async function guardPackageAccess(req,res,next){
  try{
    const id = req.params.id
    const p = (await pool.query('SELECT * FROM packages WHERE id=$1',[id])).rows[0]
    if (!p) return res.status(404).json({ error:'not_found' })
    if (p.expires_at && new Date(p.expires_at) < new Date()) return res.status(410).json({ error:'expired' })
    if (p.max_downloads && Number(p.download_count||0) >= Number(p.max_downloads)) return res.status(429).json({ error:'download_limit_reached' })

    if (p.password_hash) {
      const pwd = (req.headers['x-package-password'] || req.query.p || '')
      if (!pwd || !verifyPassword(pwd, p.password_salt, p.password_hash)) return res.status(401).json({ error:'password_required_or_invalid' })
    }

    const win = parseInt(process.env.DL_RATE_WINDOW_S || '60', 10)
    const max = parseInt(process.env.DL_RATE_MAX || '60', 10)
    const ip  = (req.headers['x-forwarded-for']?.toString().split(',')[0] || '').trim() || req.ip || ''
    await pool.query(`INSERT INTO package_downloads (package_id, ip, user_agent) VALUES ($1,$2,$3)`, [id, ip, req.headers['user-agent'] || null])
    const c = await pool.query(
      `SELECT count(*)::int AS n
       FROM package_downloads
       WHERE package_id=$1 AND ip=$2 AND created_at > now() - make_interval(secs => $3)`,
      [id, ip, win]
    )
    if ((c.rows[0]?.n || 0) > max) return res.status(429).json({ error:'rate_limited' })

    req._pkg = p; next()
  } catch (e) { console.error('[guardPackageAccess]', e); res.status(500).json({ error:'guard_failed' }) }
}

app.get('/api/pack/:id/zip', guardPackageAccess, async (req,res)=>{
  try{
    const p = req._pkg
    const id = p.id
    const f = await pool.query('SELECT key, filename, size FROM package_files WHERE package_id=$1 ORDER BY id',[id])
    if (!f.rows.length) return res.status(400).json({ error:'empty_package' })

    const zipName = `${(p.title || 'mixtli').replace(/[^\w-]+/g,'_') || 'mixtli'}.zip`
    res.setHeader('Content-Type','application/zip')
    res.setHeader('Content-Disposition',`attachment; filename="${zipName}"`)

    const archive = archiver('zip', { zlib: { level: 9 } })
    archive.on('error', err => { console.error('[ZIP]', err); try { res.status(500).end() } catch {} })
    archive.pipe(res)

    for (const row of f.rows) {
      const name = (row.filename || 'file').replace(/[\/\\]/g, '_')
      let bodyStream = null

      if (s3) {
        try { const obj = await s3.send(new GetObjectCommand({ Bucket: process.env.S3_BUCKET, Key: row.key })); bodyStream = obj.Body }
        catch (e) { console.warn('[ZIP:getObject:fail]', row.key, e?.message || e) }
      }
      if (!bodyStream) {
        try {
          const url = await buildPublicUrl(row.key)
          const r = await fetch(url)
          if (r.ok && r.body) bodyStream = asNodeStream(r.body); else console.warn('[ZIP:fetch:fail]', url, r.status)
        } catch (e) { console.warn('[ZIP:fetch:error]', row.key, e?.message || e) }
      }

      if (!bodyStream) { console.warn('[ZIP:skip]', row.key); continue }
      archive.append(bodyStream, { name })
    }

    archive.on('end', async()=>{ try { await pool.query('UPDATE packages SET download_count = download_count + 1 WHERE id=$1',[id]) } catch {} })
    await archive.finalize()
  } catch (e) { console.error('[pack_zip_failed]', e); res.status(500).json({ error:'pack_zip_failed' }) }
})

app.use((err,_req,res,_next)=>{ console.error('[ERR]', err?.message || err); res.status(500).json({ error:'internal_error', detail:String(err?.message || err) }) })

await initDb()
app.listen(parseInt(process.env.PORT || '10000',10), ()=>console.log('Mixtli Backend on :' + (process.env.PORT || '10000')))
