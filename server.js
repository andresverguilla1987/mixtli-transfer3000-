// Mixtli Transfer — Backend v2.15.0-wt
// OTP (SMS Twilio) + CORS + Presign R2 + Paquetes con password/TTL/MaxDescargas
// Conteo descargas + rate-limit por IP + ZIP robusto (GetObject + fetch->NodeStream)
// /api/pack/create => URL relativa "/share/:id"; ZIP absoluto con BACKEND_PUBLIC_ORIGIN.

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

// ---- Fallback fetch (Node <=17)
if (!globalThis.fetch) {
  const { default: nodeFetch } = await import('node-fetch')
  globalThis.fetch = nodeFetch
}

/* -------------------- CONFIG GUARD -------------------- */
const EXPECTED = {
  NODE_ENV: ['production'],
  JWT_SECRET: 'present',
  DATABASE_URL: 'present',
  S3_ENDPOINT: 'present',
  S3_BUCKET: 'present',
  S3_ACCESS_KEY_ID: 'present',
  S3_SECRET_ACCESS_KEY: 'present',
  S3_FORCE_PATH_STYLE: ['true'], // R2 => true
  ALLOWED_ORIGINS: 'json-array-nonempty',
  TWILIO_ACCOUNT_SID: 'present',
  TWILIO_AUTH_TOKEN: 'present',
  TWILIO_FROM: 'present',
  BACKEND_PUBLIC_ORIGIN: 'present'
}
function assertEnv () {
  const errs = []
  for (const [k, rule] of Object.entries(EXPECTED)) {
    const v = process.env[k]
    if (rule === 'present') { if (!v) { errs.push(`${k} vacío`) } continue }
    if (rule === 'json-array-nonempty') {
      try {
        const arr = JSON.parse(v || '[]')
        if (!Array.isArray(arr) || arr.length === 0) errs.push(`${k} debe ser JSON array no vacío`)
      } catch { errs.push(`${k} JSON inválido`) }
      continue
    }
    if (Array.isArray(rule)) { if (!rule.includes(String(v))) errs.push(`${k}=${v} no permitido`) }
  }
  if (errs.length) { console.error('[CONFIG_GUARD] ❌', errs); process.exit(1) }
  console.log('[CONFIG_GUARD] ✅ Config OK')
}
assertEnv()

/* -------------------- ENV -------------------- */
const {
  PORT = 10000,
  DATABASE_URL,
  JWT_SECRET,
  OTP_TTL_MIN = '10',

  // Email opcional
  SENDGRID_API_KEY, SENDGRID_FROM,
  SMTP_HOST, SMTP_PORT = '587', SMTP_USER, SMTP_PASS, SMTP_FROM,

  // CORS
  ALLOWED_ORIGINS,

  // Twilio
  TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_FROM,

  // S3/R2
  S3_ENDPOINT, S3_BUCKET, S3_REGION = 'auto',
  S3_ACCESS_KEY_ID, S3_SECRET_ACCESS_KEY, S3_FORCE_PATH_STYLE,
  PUBLIC_BASE_URL, FORCE_RELATIVE_URLS = 'true',
  CONTENT_DISPOSITION = '',

  // Diag
  CONFIG_DIAG_TOKEN = '',

  // Evitar proxy Netlify en ZIP
  BACKEND_PUBLIC_ORIGIN,

  // Límites por plan (MB / descargas)
  FREE_MAX_TOTAL_MB = '200',
  FREE_MAX_DOWNLOADS = '50',
  PRO_MAX_TOTAL_MB = '20480',
  PRO_MAX_DOWNLOADS = '1000',

  PACKAGE_PASSWORD_MINLEN = '4',

  // Rate descargas por IP (ventana en seg, máximo req)
  DL_RATE_WINDOW_S = '60',
  DL_RATE_MAX = '60'
} = process.env

/* -------------------- DB -------------------- */
const pool = new pg.Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } })
async function safeExec (sql) { try { await pool.query(sql) } catch {} }

async function initDb () {
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

  await pool.query(`
    CREATE TABLE IF NOT EXISTS packages (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      owner_uid UUID,
      title TEXT,
      total_size BIGINT DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      expires_at TIMESTAMPTZ,
      password_hash TEXT,
      password_salt TEXT,
      download_count BIGINT NOT NULL DEFAULT 0,
      max_downloads BIGINT,
      max_total_mb BIGINT
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

  await safeExec(`
    CREATE TABLE IF NOT EXISTS package_downloads(
      id BIGSERIAL PRIMARY KEY,
      package_id UUID REFERENCES packages(id) ON DELETE CASCADE,
      ip INET,
      user_agent TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `)
  await safeExec('CREATE INDEX IF NOT EXISTS pkg_dl_pkg_idx ON package_downloads(package_id);')
  await safeExec('CREATE INDEX IF NOT EXISTS package_files_pkg_idx ON package_files(package_id);')
  await safeExec('CREATE INDEX IF NOT EXISTS packages_expires_idx ON packages(expires_at);')

  console.log('[DB] ready')
}

/* -------------------- Helpers -------------------- */
const ttlMin = parseInt(OTP_TTL_MIN || '10', 10)
const FORCE_PATH = String(S3_FORCE_PATH_STYLE).toLowerCase() === 'true'

const rand6 = () => String(Math.floor(100000 + Math.random() * 900000))
const normalizePhone = (p) => {
  if (!p) return ''
  let s = String(p).trim().replace(/[\s\-()]/g, '')
  if (s.toLowerCase().startsWith('whatsapp:')) s = s.slice('whatsapp:'.length)
  if (!s.startsWith('+') && /^\d{10,15}$/.test(s)) s = '+' + s
  return s
}
const normalizeId = (email, phone) => (email || '').trim().toLowerCase() || normalizePhone(phone || '')
function safeName (name = '') {
  return String(name).normalize('NFKD').replace(/[\u0300-\u036f]/g,'').replace(/[^A-Za-z0-9._-]+/g,'_').slice(0,180)
}
const sanitizeEndpoint = (ep) => String(ep || '').replace(/\/+$/,'')
const sanitizeOrigin = (o) => String(o || '').replace(/\/+$/,'')
const BACKEND_ORIGIN = sanitizeOrigin(BACKEND_PUBLIC_ORIGIN)

function hashPassword(pwd) {
  const salt = randomBytes(16).toString('hex')
  const hash = scryptSync(String(pwd), salt, 32).toString('hex')
  return { salt, hash }
}
function verifyPassword(pwd, salt, goodHash) {
  if (!salt || !goodHash) return false
  const h = scryptSync(String(pwd), salt, 32).toString('hex')
  try { return timingSafeEqual(Buffer.from(h,'hex'), Buffer.from(goodHash,'hex')) } catch { return false }
}

async function createOtp (key) {
  const code = rand6()
  await pool.query(`INSERT INTO otps (key, code, exp) VALUES ($1,$2, now() + ($3 || ' minutes')::interval)`, [key, code, ttlMin])
  return code
}
async function verifyOtpDb (key, code) {
  const q = await pool.query(`SELECT id, code, exp FROM otps WHERE key=$1 ORDER BY id DESC LIMIT 1`, [key])
  if (!q.rows.length) return false
  const row = q.rows[0]
  if (row.code !== String(code)) return false
  if (new Date(row.exp) < new Date()) return false
  await pool.query(`DELETE FROM otps WHERE id=$1`, [row.id])
  return true
}

const signToken = (user) => jwt.sign({ uid: user.id, plan: user.plan }, JWT_SECRET, { expiresIn: '30d' })
function authUid (req) {
  try {
    const h = req.headers.authorization || ''
    const tok = h.startsWith('Bearer ') ? h.slice(7) : ''
    if (!tok) return null
    return jwt.verify(tok, JWT_SECRET)?.uid || null
  } catch { return null }
}
function requireAuth (req, res, next) {
  const uid = authUid(req)
  if (!uid) return res.status(401).json({ error: 'no_token' })
  req.uid = uid
  next()
}

setInterval(async ()=>{ try{ await pool.query('DELETE FROM otps WHERE exp < now()') }catch{} }, 10*60*1000)
setInterval(async ()=>{ try{ await pool.query('DELETE FROM packages WHERE expires_at IS NOT NULL AND expires_at < now()') }catch{} }, 60*60*1000)

// Mail
let smtpTransport = null
if (SMTP_HOST && SMTP_USER && SMTP_PASS) {
  const portN = parseInt(SMTP_PORT || '587', 10)
  smtpTransport = nodemailer.createTransport({ host: SMTP_HOST, port: portN, secure: portN===465, auth:{ user: SMTP_USER, pass: SMTP_PASS } })
}
async function sendMail (to, subject, text) {
  try {
    if (SENDGRID_API_KEY && SENDGRID_FROM) {
      const body = { personalizations:[{ to:[{ email: to }] }], from:{ email:SENDGRID_FROM }, subject, content:[{ type:'text/plain', value:text }] }
      const r = await fetch('https://api.sendgrid.com/v3/mail/send', { method:'POST', headers:{ Authorization:`Bearer ${SENDGRID_API_KEY}`, 'Content-Type':'application/json' }, body: JSON.stringify(body) })
      if (!r.ok) console.warn('[MAIL] SendGrid error:', await r.text())
      return
    }
    if (smtpTransport) await smtpTransport.sendMail({ from: SMTP_FROM || SMTP_USER, to, subject, text })
    else console.log('[MAIL:demo]', to, subject, text)
  } catch (e) { console.warn('[MAIL] failed', e?.message || e) }
}

// Twilio
let twilioClient = null
if (TWILIO_ACCOUNT_SID && TWILIO_AUTH_TOKEN) twilioClient = twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
async function sendSmsOnly (rawTo, text) {
  const to = normalizePhone(rawTo)
  if (!twilioClient) { console.log('[SMS:demo]', to, text); return }
  if (!TWILIO_FROM) { console.warn('[SMS] Falta TWILIO_FROM'); return }
  try { const msg = await twilioClient.messages.create({ to, from: TWILIO_FROM, body: text }); console.log('[Twilio SID]', msg.sid, 'status=', msg.status) }
  catch(e){ console.warn('[SMS ERROR]', e?.code || e?.status || '', e?.message || String(e)) }
}

// S3/R2
let s3 = null
if (S3_ENDPOINT && S3_BUCKET && S3_ACCESS_KEY_ID && S3_SECRET_ACCESS_KEY) {
  s3 = new S3Client({ region:S3_REGION, endpoint:S3_ENDPOINT, credentials:{ accessKeyId:S3_ACCESS_KEY_ID, secretAccessKey:S3_SECRET_ACCESS_KEY }, forcePathStyle:FORCE_PATH })
}
async function buildPublicUrl (key) {
  if (PUBLIC_BASE_URL) return `${sanitizeEndpoint(PUBLIC_BASE_URL)}/${key}`
  const endpoint = sanitizeEndpoint(S3_ENDPOINT)
  const host = endpoint.replace(/^https?:\/\//,'')
  return FORCE_PATH ? `${endpoint}/${S3_BUCKET}/${key}` : `https://${S3_BUCKET}.${host}/${key}`
}
const absoluteZipUrl = (id) => `${BACKEND_ORIGIN}/api/pack/${id}/zip`
function asNodeStream (body) {
  if (!body) return null
  if (typeof Readable.fromWeb === 'function' && body?.getReader) {
    try { return Readable.fromWeb(body) } catch {}
  }
  return body
}
function planLimits(plan='FREE'){
  const toMB = (n)=>Number(n||0)
  const p = String(plan||'FREE').toUpperCase()
  if (p === 'PRO') return { maxTotalMB: toMB(PRO_MAX_TOTAL_MB||20480), maxDownloads: Number(PRO_MAX_DOWNLOADS||1000) }
  return { maxTotalMB: toMB(FREE_MAX_TOTAL_MB||200), maxDownloads: Number(FREE_MAX_DOWNLOADS||50) }
}

/* -------------------- App / CORS -------------------- */
const app = express()
let ORIGINS = []
try { ORIGINS = JSON.parse(ALLOWED_ORIGINS || '[]') } catch {}
const isNetlifyPreview = (origin)=>{ try { return /\.netlify\.app$/i.test(new URL(origin).hostname) } catch { return false } }
const corsMw = cors({
  origin: (o, cb) => { if (!o) return cb(null,true); if (ORIGINS.includes(o) || isNetlifyPreview(o)) return cb(null,true); return cb(new Error('origin_not_allowed')) },
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization','x-admin-token','x-cron-token','x-mixtli-token','x-package-password'],
  optionsSuccessStatus: 204
})
app.use((req,res,next)=>corsMw(req,res,(err)=>{ if (err?.message==='origin_not_allowed') return res.status(403).json({ error:'origin_not_allowed', origin:req.headers.origin||null }); next() }))
app.options('*', corsMw)
app.set('trust proxy', 1)
app.use(express.json({ limit:'4mb' }))

/* -------------------- Rate-limit OTP -------------------- */
const otpLimiter = rateLimit({ windowMs: 5*60*1000, max: 8, standardHeaders:true, legacyHeaders:false, skip: (req)=>req.method==='OPTIONS' })

/* -------------------- Rutas base -------------------- */
app.get('/', (_req,res)=>res.type('text/plain').send('OK'))
app.get('/api/health', (_req,res)=>res.json({ ok:true, time:new Date().toISOString(), ver:'2.15.0-wt', channel:'sms-only' }))
app.head('/api/health', (_req,res)=>res.status(200).end())

// Diag
app.get('/api/diag', (req,res)=>{
  const tok = req.headers['x-config-token'] || ''
  if (!CONFIG_DIAG_TOKEN || tok !== CONFIG_DIAG_TOKEN) return res.status(401).json({ ok:false })
  res.json({ ok:true, node:process.version, ver:'2.15.0-wt', cors_origins:ORIGINS, force_path:String(S3_FORCE_PATH_STYLE), public_base:!!PUBLIC_BASE_URL, backend_origin:BACKEND_ORIGIN })
})

app.get('/api/auth/whoami', (req,res)=>{ const uid = authUid(req); if (!uid) return res.status(401).json({ ok:false }); res.json({ ok:true, uid }) })

// Aliases sin /api
app.post('/auth/register', (req,_res,next)=>{ req.url = '/api/auth/register'; next() })
app.post('/auth/verify-otp', (req,_res,next)=>{ req.url = '/api/auth/verify-otp'; next() })
app.post('/auth/verify', (req,_res,next)=>{ req.url = '/api/auth/verify-otp'; next() })

// OTP: enviar
app.post('/api/auth/register', otpLimiter, async (req,res)=>{
  try{
    const { email='', phone='' } = req.body || {}
    const id = normalizeId(email, phone)
    if (!id) return res.status(400).json({ error:'email_or_phone_required' })
    const code = await createOtp(id)
    if (email) await sendMail(email.trim().toLowerCase(), 'Tu código Mixtli', `Tu código es: ${code}\nExpira en ${ttlMin} minutos.`)
    else       await sendSmsOnly(phone, `Mixtli: tu código es ${code}. Expira en ${ttlMin} min.`)
    res.json({ ok:true, msg:'otp_sent' })
  }catch(e){ console.error('[register_failed]', e); res.status(500).json({ error:'otp_send_failed' }) }
})

// OTP: verificar
app.post('/api/auth/verify-otp', async (req,res)=>{
  try{
    const { email='', phone='', otp } = req.body || {}
    const id = normalizeId(email, phone)
    if (!id || !otp) return res.status(400).json({ error:'need_id_and_otp' })
    const ok = await verifyOtpDb(id, otp)
    if (!ok) return res.status(400).json({ error:'otp_invalid' })

    let row
    if (email) {
      row = (await pool.query(
        `INSERT INTO users (email,plan) VALUES ($1,'FREE')
         ON CONFLICT (email) DO UPDATE SET updated_at=now()
         RETURNING id,email,phone,plan,plan_expires_at`, [email.trim().toLowerCase()]
      )).rows[0]
    } else {
      row = (await pool.query(
        `INSERT INTO users (phone,plan) VALUES ($1,'FREE')
         ON CONFLICT (phone) DO UPDATE SET updated_at=now()
         RETURNING id,email,phone,plan,plan_expires_at`, [normalizePhone(phone)]
      )).rows[0]
    }
    const token = signToken(row)
    res.json({ token, user: row })
  }catch(e){ console.error('[verify_failed]', e); res.status(500).json({ error:'verify_failed' }) }
})

/* -------------------- Presign S3/R2 -------------------- */
app.post('/api/presign', requireAuth, async (req,res)=>{
  try{
    if (!s3) return res.status(500).json({ error:'s3_not_configured' })
    const { filename, type='application/octet-stream' } = req.body || {}
    const base = safeName(filename || `file-${Date.now()}`)
    const key  = `uploads/${new Date().toISOString().slice(0,10)}/${crypto.randomUUID()}-${base}`
    const params = { Bucket:S3_BUCKET, Key:key, ContentType:type }
    if (CONTENT_DISPOSITION) params.ContentDisposition = CONTENT_DISPOSITION
    const cmd = new PutObjectCommand(params)
    const url = await getSignedUrl(s3, cmd, { expiresIn: 300 })
    res.json({ method:'PUT', url, key, publicUrl: await buildPublicUrl(key) })
  }catch(e){ console.error('[presign_failed]', e); res.status(500).json({ error:'presign_failed', detail:String(e?.message||e) }) }
})

app.post('/api/complete', requireAuth, async (req,res)=>{
  try{ const { key } = req.body || {}; if (!key) return res.status(400).json({ error:'key_required' }); res.json({ ok:true, publicUrl: await buildPublicUrl(key) }) }
  catch(e){ console.error('[complete_failed]', e); res.status(500).json({ error:'complete_failed' }) }
})

/* -------------------- PACKAGES -------------------- */
app.post('/api/pack/create', requireAuth, async (req,res)=>{
  try{
    const { title='Mis archivos', ttlDays=30, files=[], password='', maxDownloads, maxTotalMB } = req.body || {}
    if (!Array.isArray(files) || files.length===0) return res.status(400).json({ error:'no_files' })

    const userRow = (await pool.query('SELECT id, plan FROM users WHERE id=$1',[req.uid])).rows[0]
    const lim = planLimits(userRow?.plan || 'FREE')

    const totalSize = files.reduce((a,f)=>a+(Number(f.size)||0), 0)
    const totalMB   = Math.ceil(totalSize / (1024*1024))
    const effMaxMB  = Math.min(Number(maxTotalMB || lim.maxTotalMB), lim.maxTotalMB)
    if (totalMB > effMaxMB) return res.status(400).json({ error:'package_too_big', max_mb: effMaxMB, got_mb: totalMB })

    const ttl = Math.min(Math.max(parseInt(ttlDays||30,10),1),180)

    let password_hash=null, password_salt=null
    const minLen = parseInt(PACKAGE_PASSWORD_MINLEN || '4', 10)
    if (password) {
      if (String(password).length < minLen) return res.status(400).json({ error:'weak_password', min:minLen })
      const h = hashPassword(password); password_hash=h.hash; password_salt=h.salt
    }

    let effMaxDownloads = null
    if (maxDownloads != null) {
      effMaxDownloads = Math.min(Number(maxDownloads||0), lim.maxDownloads)
      if (effMaxDownloads <= 0) effMaxDownloads = null
    }

    const r = await pool.query(
      `INSERT INTO packages (owner_uid,title,total_size,expires_at,password_hash,password_salt,max_downloads,max_total_mb)
       VALUES ($1,$2,$3, now() + ($4 || ' days')::interval, $5,$6,$7,$8)
       RETURNING id, expires_at`,
      [req.uid, title, totalSize, ttl, password_hash, password_salt, effMaxDownloads, effMaxMB]
    )
    const pid = r.rows[0].id

    const values = []
    const params = []
    files.forEach(f=>{
      params.push(pid, f.key, f.name || null, Number(f.size)||0, f.type || null)
      values.push(`($${params.length-4},$${params.length-3},$${params.length-2},$${params.length-1},$${params.length})`)
    })
    await pool.query(`INSERT INTO package_files (package_id,key,filename,size,content_type) VALUES ${values.join(',')}`, params)

    const sharePath = `/share/${pid}`
    const relative  = String(FORCE_RELATIVE_URLS).toLowerCase() === 'true'
    const url = relative ? sharePath : ((PUBLIC_BASE_URL||'') ? (sanitizeEndpoint(PUBLIC_BASE_URL)+sharePath) : sharePath)

    res.json({ ok:true, id:pid, url, expires_at:r.rows[0].expires_at, password: !!password })
  }catch(e){ console.error('[pack_create_failed]', e); res.status(500).json({ error:'pack_create_failed' }) }
})

// JSON del paquete
app.get('/api/pack/:id', async (req,res)=>{
  try{
    const id = req.params.id
    const p  = await pool.query('SELECT * FROM packages WHERE id=$1',[id])
    if (!p.rows.length) return res.status(404).json({ error:'not_found' })
    const f  = await pool.query('SELECT key,filename,size,content_type FROM package_files WHERE package_id=$1 ORDER BY id',[id])
    const files = await Promise.all(f.rows.map(async r=>({ name:r.filename || 'file', size:Number(r.size)||0, type:r.content_type, url: await buildPublicUrl(r.key) })))
    res.json({ id, title:p.rows[0].title, total_size:Number(p.rows[0].total_size)||0, expires_at:p.rows[0].expires_at, files, zip_url: absoluteZipUrl(id) })
  }catch(e){ console.error('[pack_fetch_failed]', e); res.status(500).json({ error:'pack_fetch_failed' }) }
})

// Página pública
app.get('/share/:id', async (req,res)=>{
  try{
    const id = req.params.id
    const p = await pool.query('SELECT * FROM packages WHERE id=$1',[id])
    if (!p.rows.length) return res.status(404).type('text/plain').send('Paquete no encontrado')
    const needPwd = !!p.rows[0].password_hash

    const f = await pool.query('SELECT key,filename,size FROM package_files WHERE package_id=$1 ORDER BY id',[id])
    const items = await Promise.all(f.rows.map(async r=>{
      const url = await buildPublicUrl(r.key)
      const name = (r.filename || 'file').replace(/</g,'&lt;').replace(/>/g,'&gt;')
      const mb = (Number(r.size||0)/1048576).toFixed(2)
      return `<li><a href="${url}" target="_blank" rel="noopener">${name}</a> — ${mb} MB</li>`
    }))
    const zipAbs = absoluteZipUrl(id)
    const btn = needPwd
      ? `<button id="dlAll" style="padding:8px 12px;background:#34d399;color:#001;border-radius:8px;border:0">Descargar todo (ZIP)</button>`
      : `<a href="${zipAbs}" style="display:inline-block;padding:8px 12px;background:#34d399;color:#001;border-radius:8px;text-decoration:none">Descargar todo (ZIP)</a>`

    res.type('html').send(`<!doctype html><meta charset="utf-8">
      <title>${(p.rows[0].title || 'Descargas').replace(/</g,'&lt;').replace(/>/g,'&gt;')}</title>
      <meta name="viewport" content="width=device-width,initial-scale=1" />
      <div style="font-family:system-ui;padding:24px;max-width:820px;margin:auto;color:#e5e7eb;background:#0b0f17">
        <h1 style="margin:0 0 8px;font-size:28px;color:#fff">${(p.rows[0].title || 'Descargas').replace(/</g,'&lt;').replace(/>/g,'&gt;')}</h1>
        <p style="margin:0 0 16px;color:#9ca3af">Expira: ${p.rows[0].expires_at}</p>
        <p>${btn}</p>
        <ul style="line-height:1.9">${items.join('')}</ul>
      </div>
      <script>
        (function(){
          const needPwd = ${needPwd ? 'true':'false'};
          const zipUrl = ${JSON.stringify(zipAbs)};
          if (!needPwd) return;
          const btn = document.getElementById('dlAll');
          btn?.addEventListener('click', async () => {
            const pwd = prompt('Este paquete está protegido. Ingresa la contraseña:');
            if (!pwd) return;
            try {
              const r = await fetch(zipUrl, { headers: { 'x-package-password': pwd } });
              if (!r.ok) { alert('Contraseña incorrecta o límite alcanzado.'); return; }
              const blob = await r.blob();
              const a = document.createElement('a');
              a.href = URL.createObjectURL(blob);
              a.download = 'descarga.zip';
              document.body.appendChild(a); a.click(); a.remove();
              setTimeout(()=>URL.revokeObjectURL(a.href), 10000);
            } catch(e) { alert('Error al descargar.'); }
          });
        })();
      </script>`)
  }catch(e){ console.error('[share_render_failed]', e); res.status(500).type('text/plain').send('Error interno') }
})

/* -------- Guard de acceso ZIP: password + límites + rate por IP -------- */
async function guardPackageAccess(req,res,next){
  try{
    const id = req.params.id
    const p  = (await pool.query('SELECT * FROM packages WHERE id=$1',[id])).rows[0]
    if (!p) return res.status(404).json({ error:'not_found' })
    if (p.expires_at && new Date(p.expires_at) < new Date()) return res.status(410).json({ error:'expired' })

    if (p.max_downloads && Number(p.download_count||0) >= Number(p.max_downloads))
      return res.status(429).json({ error:'download_limit_reached' })

    if (p.password_hash) {
      const pwd = (req.headers['x-package-password'] || req.query.p || '')
      if (!pwd || !verifyPassword(pwd, p.password_salt, p.password_hash))
        return res.status(401).json({ error:'password_required_or_invalid' })
    }

    const win = parseInt(DL_RATE_WINDOW_S || '60', 10)
    const max = parseInt(DL_RATE_MAX || '60', 10)
    const ip  = req.headers['x-forwarded-for']?.toString().split(',')[0]?.trim() || req.ip || ''
    await pool.query(`INSERT INTO package_downloads (package_id, ip, user_agent) VALUES ($1,$2,$3)`, [id, ip, req.headers['user-agent'] || null])
    const c = await pool.query(`
      SELECT count(*)::int AS n
      FROM package_downloads
      WHERE package_id=$1 AND ip=$2 AND created_at > now() - make_interval(secs => $3)
    `,[id, ip, win])
    if ((c.rows[0]?.n || 0) > max) return res.status(429).json({ error:'rate_limited' })

    req._pkg = p
    next()
  }catch(e){ console.error('[guardPackageAccess]', e); res.status(500).json({ error:'guard_failed' }) }
}

// ZIP streaming
app.get('/api/pack/:id/zip', guardPackageAccess, async (req,res)=>{
  try{
    const p = req._pkg
    const id = p.id
    const f = await pool.query('SELECT key,filename,size FROM package_files WHERE package_id=$1 ORDER BY id',[id])
    if (!f.rows.length) return res.status(400).json({ error:'empty_package' })

    const zipName = `${(p.title || 'mixtli').replace(/[^\w-]+/g,'_') || 'mixtli'}.zip`
    res.setHeader('Content-Type','application/zip')
    res.setHeader('Content-Disposition', `attachment; filename="${zipName}"`)

    const archive = archiver('zip', { zlib:{ level:9 } })
    archive.on('error', err => { console.error('[ZIP]', err); try{ res.status(500).end() }catch{} })
    archive.pipe(res)

    for (const row of f.rows) {
      const name = (row.filename || 'file').replace(/[\/\\]/g,'_')
      let bodyStream = null

      if (s3) {
        try { const obj = await s3.send(new GetObjectCommand({ Bucket:S3_BUCKET, Key:row.key })); bodyStream = obj.Body }
        catch(e){ console.warn('[ZIP:getObject:fail]', row.key, e?.message || e) }
      }
      if (!bodyStream) {
        try {
          const url = await buildPublicUrl(row.key)
          const r = await fetch(url)
          if (r.ok && r.body) bodyStream = asNodeStream(r.body)
          else console.warn('[ZIP:fetch:fail]', url, r.status)
        } catch(e){ console.warn('[ZIP:fetch:error]', row.key, e?.message || e) }
      }

      if (!bodyStream) { console.warn('[ZIP:skip]', row.key); continue }
      archive.append(bodyStream, { name })
    }

    archive.on('end', async ()=>{ try{ await pool.query('UPDATE packages SET download_count = download_count + 1 WHERE id=$1',[id]) }catch{} })
    await archive.finalize()
  }catch(e){ console.error('[pack_zip_failed]', e); res.status(500).json({ error:'pack_zip_failed' }) }
})

/* -------------------- Debug -------------------- */
app.get('/api/debug/twilio/:sid', async (req,res)=>{
  try{
    if (!twilioClient) return res.status(500).json({ error:'no_twilio_client' })
    const msg = await twilioClient.messages(req.params.sid).fetch()
    res.json({ sid:msg.sid, status:msg.status, to:msg.to, from:msg.from, errorCode:msg.errorCode, errorMessage:msg.errorMessage, dateCreated:msg.dateCreated, dateSent:msg.dateSent, dateUpdated:msg.dateUpdated })
  }catch(e){ res.status(500).json({ error:String(e?.message||e) }) }
})
app.get('/api/debug/twilio', async (_req,res)=>{
  try{
    if (!twilioClient) return res.status(500).json({ error:'no_twilio_client' })
    const msgs = await twilioClient.messages.list({ limit:10 })
    res.json(msgs.map(m=>({ sid:m.sid, status:m.status, to:m.to, from:m.from, errorCode:m.errorCode, errorMessage:m.errorMessage })))
  }catch(e){ res.status(500).json({ error:String(e?.message||e) }) }
})
app.get('/api/debug/origins', (req,res)=>res.json({ allowed:ORIGINS, requestOrigin:req.headers.origin||null }))

// Error global
app.use((err,_req,res,_next)=>{ console.error('[ERR]', err?.message || err); res.status(500).json({ error:'internal_error', detail:String(err?.message||err) }) })

// Boot
await initDb()
app.listen(parseInt(PORT,10), ()=>console.log('Mixtli Backend on :' + PORT))
