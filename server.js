// MixtliTransfer3000 Backend v2.5.1 (Render pack)
import 'dotenv/config'
import express from 'express'
import cors from 'cors'
import { randomUUID, createHash } from 'node:crypto'
import jwt from 'jsonwebtoken'
import pg from 'pg'
import { S3Client, PutObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3'
import { getSignedUrl } from '@aws-sdk/s3-request-presigner'
import nodemailer from 'nodemailer'

const num = (x)=> Math.max(0, parseInt(String(x??'0'),10) || 0)
const clamp = (n,a,b)=> Math.max(a, Math.min(b,n))
const extOf = (f='') => { const i=f.lastIndexOf('.'); return i>-1? f.slice(i+1).toLowerCase(): '' }
const clientIp = (req)=>{ const xf=req.headers['x-forwarded-for']; const ip=(Array.isArray(xf)?xf[0]:(xf||'')).split(',')[0].trim()||req.ip||'0.0.0.0'; return ip }
const sha256hex = (s)=> createHash('sha256').update(String(s)).digest('hex')
const hashIp = (ip, salt)=> sha256hex(String(salt||'') + '|' + String(ip))
const cryptoId = (p='L')=> p + randomUUID().replace(/-/g,'').slice(0,11)

const SEALED = {
  S3_ENDPOINT: process.env.S3_ENDPOINT || '',
  S3_BUCKET: process.env.S3_BUCKET || '',
  S3_REGION: process.env.S3_REGION || 'auto',
  S3_FORCE_PATH_STYLE: (process.env.S3_FORCE_PATH_STYLE || 'true') === 'true',
  ALLOWED_ORIGINS: (()=>{
    try{ const v=process.env.ALLOWED_ORIGINS
      if(!v) return ['https://lighthearted-froyo-9dd448.netlify.app','http://localhost:8888']
      if(v.trim().startsWith('[')) return JSON.parse(v)
      if(v.includes(',')) return v.split(',').map(s=>s.trim()).filter(Boolean)
      return [v.trim()] }catch{ return ['https://lighthearted-froyo-9dd448.netlify.app','http://localhost:8888'] }
  })()
}

const {
  PORT = process.env.PORT || 10000,
  S3_ACCESS_KEY_ID,
  S3_SECRET_ACCESS_KEY,
  DATABASE_URL,
  JWT_SECRET = 'change_me',
  OTP_TTL_MIN = '10',
  FREE_MAX_UPLOAD_MB = '3584',
  FREE_LINK_TTL_DEFAULT_DAYS = '3',
  FREE_LINK_TTL_MAX_DAYS = '30',
  PRO_MAX_PERIOD_GB = '400',
  PRO_LINK_TTL_DAYS = '7',
  PROMAX_LINK_TTL_DAYS = '22',
  UPLOAD_URL_TTL_SECONDS = '3600',
  DOWNLOAD_URL_TTL_SECONDS_MAX = '86400',
  PUBLIC_BASE_URL,
  SENDGRID_API_KEY,
  SENDGRID_FROM,
  SMTP_HOST,
  SMTP_PORT = '587',
  SMTP_USER,
  SMTP_PASS,
  SMTP_FROM,
  ADMIN_TOKEN,
  CRON_TOKEN,
  RL_AUTH_PER_MIN = '6',
  RL_PRESIGN_PER_MIN = '30',
  IP_SALT = ''
} = process.env

if (!DATABASE_URL) { console.error('[FATAL] Missing DATABASE_URL'); process.exit(1) }

const MB = 1024*1024
const pool = new pg.Pool({ connectionString: DATABASE_URL })
const s3 = new S3Client({ region: SEALED.S3_REGION, endpoint: SEALED.S3_ENDPOINT, credentials: { accessKeyId: S3_ACCESS_KEY_ID||'x', secretAccessKey: S3_SECRET_ACCESS_KEY||'x' }, forcePathStyle: !!SEALED.S3_FORCE_PATH_STYLE })

const FREECFG = { sizeCap: parseInt(FREE_MAX_UPLOAD_MB)*MB, ttlDefaultDays: parseInt(FREE_LINK_TTL_DEFAULT_DAYS), ttlMaxDays: parseInt(FREE_LINK_TTL_MAX_DAYS) }
const PROCFG = { ttlDays: 7 }
const PMCFG = { ttlDays: 22 }

let smtpTransport = null
if (SMTP_HOST && SMTP_USER && SMTP_PASS) {
  const portN = parseInt(SMTP_PORT||'587',10)
  smtpTransport = nodemailer.createTransport({ host: SMTP_HOST, port: portN, secure: portN===465, auth: { user: SMTP_USER, pass: SMTP_PASS } })
}
async function sendMail(to, subject, text) {
  try{
    if (SENDGRID_API_KEY && SENDGRID_FROM) {
      const body = { personalizations:[{ to:[{email:to}] }], from:{email:SENDGRID_FROM}, subject, content:[{type:'text/plain', value:text}] }
      const r = await fetch('https://api.sendgrid.com/v3/mail/send',{ method:'POST', headers:{'Authorization':`Bearer ${SENDGRID_API_KEY}`,'Content-Type':'application/json'}, body: JSON.stringify(body) })
      if(!r.ok) console.warn('[MAIL] SendGrid', await r.text())
      return
    }
    if (smtpTransport && (SMTP_FROM || to)) { await smtpTransport.sendMail({ from: SMTP_FROM || SMTP_USER, to, subject, text }); return }
    console.log('[MAIL:demo]', to, subject, text)
  }catch(e){ console.warn('[MAIL] failed', e.message) }
}

const app = express()
app.set('trust proxy', true)
app.use(cors({ origin:(o,cb)=>{ if(!o) return cb(null,true); if(SEALED.ALLOWED_ORIGINS.includes(o)) return cb(null,true); cb(new Error('origin_not_allowed')); }, methods:['GET','POST','PUT','OPTIONS'], allowedHeaders:['Content-Type','Authorization','x-admin-token','x-cron-token'] }))
app.use(express.json({ limit:'2mb' }))
app.get('/', (_req,res)=> res.type('text/plain').send('OK'))
app.get('/api/health', (_req,res)=> res.json({ ok:true, time:new Date().toISOString() }))

function signToken(user){ return jwt.sign({ uid:user.id, plan:user.plan }, JWT_SECRET, { expiresIn:'30d' }) }

async function initDb(){
  await pool.query('CREATE EXTENSION IF NOT EXISTS "pgcrypto";')
  await pool.query('CREATE EXTENSION IF NOT EXISTS "uuid-ossp";')
  await pool.query('CREATE TABLE IF NOT EXISTS users ( id UUID PRIMARY KEY DEFAULT gen_random_uuid(), email TEXT, phone TEXT, plan TEXT NOT NULL DEFAULT 'FREE', plan_expires_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now() );')
  await pool.query('CREATE TABLE IF NOT EXISTS links ( id BIGSERIAL PRIMARY KEY, slug TEXT UNIQUE, user_id UUID, anon_ip TEXT, plan TEXT NOT NULL, key TEXT NOT NULL, filename TEXT NOT NULL, content_type TEXT NOT NULL DEFAULT 'application/octet-stream', size_bytes BIGINT NOT NULL DEFAULT 0, expires_at TIMESTAMPTZ NOT NULL, active BOOLEAN NOT NULL DEFAULT TRUE, password_hash TEXT, password_salt TEXT, password_hint TEXT, brand_json JSONB, max_downloads INT, downloads INT NOT NULL DEFAULT 0, created_at TIMESTAMPTZ NOT NULL DEFAULT now() );')
  await pool.query('CREATE UNIQUE INDEX IF NOT EXISTS idx_links_key_unique ON links(key);')
  await pool.query('CREATE INDEX IF NOT EXISTS idx_links_expires ON links(expires_at);')
  await pool.query('CREATE TABLE IF NOT EXISTS otps ( id BIGSERIAL PRIMARY KEY, key TEXT NOT NULL, code TEXT NOT NULL, exp TIMESTAMPTZ NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now() );')
  console.log('[DB] ready')
}
await initDb()

async function createOtp(id, ttlMin){ const code=String(Math.floor(100000+Math.random()*900000)); await pool.query('INSERT INTO otps (key,code,exp) VALUES ($1,$2, now() + ($3||' minutes')::interval)', [id, code, ttlMin]); return code }
async function verifyOtpDb(key, code){
  const q=await pool.query('SELECT id,code,exp FROM otps WHERE key=$1 ORDER BY id DESC LIMIT 1', [key])
  if(!q.rows.length) return false
  const row=q.rows[0]; if(row.code!==String(code)) return false; if(new Date(row.exp)<new Date()) return false
  await pool.query('DELETE FROM otps WHERE id=$1', [row.id]); return true
}

app.post('/api/auth/register', async (req,res)=>{
  try{
    const { email, phone }=req.body||{}; const id=(email&&String(email).toLowerCase())||(phone&&String(phone))||''
    if(!id) return res.status(400).json({ error:'email_or_phone_required' })
    const code = await createOtp(id, OTP_TTL_MIN)
    if(email) await sendMail(id, 'Tu código Mixtli', `Tu código es: ${code}\nExpira en ${OTP_TTL_MIN} minutos.`)
    res.json({ ok:true, msg:'otp_sent' })
  }catch(e){ console.error(e); res.status(500).json({ error:'otp_send_failed' }) }
})

app.post('/api/auth/verify-otp', async (req,res)=>{
  const { email, phone, otp }=req.body||{}; const id=(email&&String(email).toLowerCase())||(phone&&String(phone))||''
  if(!id||!otp) return res.status(400).json({ error:'need_id_and_otp' })
  const ok = await verifyOtpDb(id, otp); if(!ok) return res.status(400).json({ error:'otp_invalid' })
  const r = email
    ? await pool.query('INSERT INTO users (email,plan) VALUES ($1,'FREE') ON CONFLICT (email) DO UPDATE SET updated_at=now() RETURNING id,email,phone,plan,plan_expires_at',[email.toLowerCase()])
    : await pool.query('INSERT INTO users (phone,plan) VALUES ($1,'FREE') ON CONFLICT (phone) DO UPDATE SET updated_at=now() RETURNING id,email,phone,plan,plan_expires_at',[phone])
  const user = r.rows[0]
  const token=signToken(user); res.json({ token, user })
})

app.listen(parseInt(PORT,10), ()=> console.log('MixtliTransfer3000 on :' + PORT))
