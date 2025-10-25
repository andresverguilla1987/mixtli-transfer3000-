// Mixtli Transfer – Backend (OTP + Health) v2.5.1 with CORS fixes
import 'dotenv/config'
import express from 'express'
import cors from 'cors'
import jwt from 'jsonwebtoken'
import pg from 'pg'
import nodemailer from 'nodemailer'

const num = (x)=> Math.max(0, parseInt(String(x ?? '0'), 10) || 0)

const {
  PORT = process.env.PORT || 10000,
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
  ALLOWED_ORIGINS = '["http://localhost:8888","https://lighthearted-froyo-9dd448.netlify.app"]'
} = process.env

if (!DATABASE_URL) { console.error('[FATAL] Missing DATABASE_URL'); process.exit(1) }

const pool = new pg.Pool({ connectionString: DATABASE_URL })

async function initDb() {
  await pool.query('CREATE EXTENSION IF NOT EXISTS "pgcrypto";')
  await pool.query('CREATE EXTENSION IF NOT EXISTS "uuid-ossp";')
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      email TEXT,
      phone TEXT,
      plan TEXT NOT NULL DEFAULT 'FREE',
      plan_expires_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );`)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS otps (
      id BIGSERIAL PRIMARY KEY,
      key TEXT NOT NULL,
      code TEXT NOT NULL,
      exp TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );`)
  await pool.query(`DO $$
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

async function createOtp(key, ttlMin) {
  const code = String(Math.floor(100000 + Math.random() * 900000))
  await pool.query(`INSERT INTO otps (key, code, exp) VALUES ($1, $2, now() + ($3 || ' minutes')::interval)`, [key, code, ttlMin])
  return code
}

async function verifyOtpDb(key, code) {
  const q = await pool.query(`SELECT id, code, exp FROM otps WHERE key=$1 ORDER BY id DESC LIMIT 1`, [key])
  if (!q.rows.length) return false
  const row = q.rows[0]
  if (row.code !== String(code)) return false
  if (new Date(row.exp) < new Date()) return false
  await pool.query(`DELETE FROM otps WHERE id=$1`, [row.id])
  return true
}

function signToken(user) {
  return jwt.sign({ uid:user.id, plan:user.plan }, JWT_SECRET, { expiresIn:'30d' })
}

let smtpTransport = null
if (SMTP_HOST && SMTP_USER && SMTP_PASS) {
  const portN = parseInt(SMTP_PORT || '587', 10)
  smtpTransport = nodemailer.createTransport({ host: SMTP_HOST, port: portN, secure: portN === 465, auth: { user: SMTP_USER, pass: SMTP_PASS } })
}

async function sendMail(to, subject, text) {
  try {
    if (SENDGRID_API_KEY && SENDGRID_FROM) {
      const body = { personalizations: [{ to: [{ email: to }] }], from: { email: SENDGRID_FROM }, subject, content: [{ type: 'text/plain', value: text }] }
      const r = await fetch('https://api.sendgrid.com/v3/mail/send', { method:'POST', headers:{ 'Authorization':`Bearer ${SENDGRID_API_KEY}`, 'Content-Type':'application/json' }, body: JSON.stringify(body) })
      if (!r.ok) console.warn('[MAIL] SendGrid error:', await r.text())
      return
    }
    if (smtpTransport) { await smtpTransport.sendMail({ from: SMTP_FROM || SMTP_USER, to, subject, text }); return }
    console.log('[MAIL:demo]', to, subject, text)
  } catch (e) {
    console.warn('[MAIL] failed', e?.message || e)
  }
}

const app = express()

let ORIGINS = []
try { ORIGINS = JSON.parse(ALLOWED_ORIGINS) } catch { ORIGINS = [] }
const corsMw = cors({ origin: (o, cb)=>{ if(!o) return cb(null,true); if(ORIGINS.includes(o)) return cb(null,true); cb(new Error('origin_not_allowed')) }, methods:['GET','POST','PUT','OPTIONS'], allowedHeaders:['Content-Type','Authorization','x-admin-token','x-cron-token'], optionsSuccessStatus:204 })
app.use(corsMw)
app.options('*', corsMw)

app.set('trust proxy', true)
app.use(express.json({ limit:'2mb' }))

app.get('/', (_req,res)=> res.type('text/plain').send('OK'))
app.get('/api/health', (_req,res)=> res.json({ ok:true, time:new Date().toISOString() }))

app.post('/api/auth/register', async (req,res)=>{
  try{
    const { email, phone }=req.body||{}
    const id=(email&&String(email).toLowerCase())||(phone&&String(phone))||''
    if(!id) return res.status(400).json({ error:'email_or_phone_required' })
    const code=await createOtp(id, OTP_TTL_MIN)
    if(email) await sendMail(id, 'Tu código Mixtli', `Tu código es: ${code}
Expira en ${OTP_TTL_MIN} minutos.`)
    res.json({ ok:true, msg:'otp_sent' })
  }catch(e){ console.error(e); res.status(500).json({ error:'otp_send_failed' }) }
})

app.post('/api/auth/verify', (req,_res,next)=>{ console.log('[ALIAS] /api/auth/verify -> /api/auth/verify-otp'); req.url='/api/auth/verify-otp'; next() })

app.post('/api/auth/verify-otp', async (req,res)=>{
  try{
    console.log('[VERIFY-OTP] body:', req.body)
    const { email, phone, otp }=req.body||{}
    const id=(email&&String(email).toLowerCase())||(phone&&String(phone))||''
    if(!id||!otp) return res.status(400).json({ error:'need_id_and_otp' })
    const ok=await verifyOtpDb(id, otp)
    if(!ok) return res.status(400).json({ error:'otp_invalid' })

    let row
    if(email){
      const r=await pool.query(`INSERT INTO users (email,plan) VALUES ($1,'FREE') ON CONFLICT (email) DO UPDATE SET updated_at=now() RETURNING id,email,phone,plan,plan_expires_at`, [email.toLowerCase()])
      row=r.rows[0]
    } else {
      const r=await pool.query(`INSERT INTO users (phone,plan) VALUES ($1,'FREE') ON CONFLICT (phone) DO UPDATE SET updated_at=now() RETURNING id,email,phone,plan,plan_expires_at`, [phone])
      row=r.rows[0]
    }
    const token=signToken(row)
    res.json({ token, user: row })
  }catch(e){ console.error(e); res.status(500).json({ error:'verify_failed' }) }
})

app.use((err,_req,res,_next)=>{ console.error('[ERR]', err?.message||err); res.status(500).json({ error:'internal_error', detail:String(err?.message||err) }) })

await initDb()
app.listen(parseInt(PORT,10), ()=> console.log('Mixtli Backend on :' + PORT))
