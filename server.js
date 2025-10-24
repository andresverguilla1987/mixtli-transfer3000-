// MixtliTransfer3000 Backend v2.2.0 — Auth OTP + Upgrade PRO/PROMAX con expiración (no-FK)
import 'dotenv/config'
import express from 'express'
import cors from 'cors'
import { randomUUID, createHash } from 'node:crypto'
import jwt from 'jsonwebtoken'
import pg from 'pg'
import { S3Client, PutObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3'
import { getSignedUrl } from '@aws-sdk/s3-request-presigner'

// ---------- helpers/env ----------
const SEALED = {
  S3_ENDPOINT: process.env.S3_ENDPOINT || 'https://8351c372dedf0e354a3196aff085f0ae.r2.cloudflarestorage.com',
  S3_BUCKET: process.env.S3_BUCKET || 'mixtlitransfer3000',
  S3_REGION: process.env.S3_REGION || 'auto',
  S3_FORCE_PATH_STYLE: (process.env.S3_FORCE_PATH_STYLE || 'true') === 'true',
  ALLOWED_ORIGINS: (()=>{
    try{
      const v=process.env.ALLOWED_ORIGINS
      if(!v) return ['https://lighthearted-froyo-9dd448.netlify.app','http://localhost:8888']
      if(v.trim().startsWith('[')) return JSON.parse(v)
      if(v.includes(',')) return v.split(',').map(s=>s.trim()).filter(Boolean)
      return [v.trim()]
    }catch{ return ['https://lighthearted-froyo-9dd448.netlify.app','http://localhost:8888'] }
  })()
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
  PRO_PERIOD_DAYS = '30',
  PROMAX_PERIOD_DAYS = '30',
  UPLOAD_URL_TTL_SECONDS = '3600',
  DOWNLOAD_URL_TTL_SECONDS_MAX = '86400',
  PUBLIC_BASE_URL
} = process.env

if (!SEALED.S3_ENDPOINT || !SEALED.S3_BUCKET || !S3_ACCESS_KEY_ID || !S3_SECRET_ACCESS_KEY) { console.error('[FATAL] Missing R2 creds'); process.exit(1) }
if (!DATABASE_URL) { console.error('[FATAL] Missing DATABASE_URL'); process.exit(1) }

const MB = 1024*1024
const pool = new pg.Pool({ connectionString: DATABASE_URL })
const s3 = new S3Client({ region: SEALED.S3_REGION, endpoint: SEALED.S3_ENDPOINT, credentials: { accessKeyId: S3_ACCESS_KEY_ID, secretAccessKey: S3_SECRET_ACCESS_KEY }, forcePathStyle: !!SEALED.S3_FORCE_PATH_STYLE })

const num = (x)=> Math.max(0, parseInt(String(x??'0'),10) || 0)
const clamp = (n,a,b)=> Math.max(a, Math.min(b,n))
const extOf = (f='') => { const i=f.lastIndexOf('.'); return i>-1? f.slice(i+1).toLowerCase(): '' }
const clientIp = (req)=>{ const xf=req.headers['x-forwarded-for']; const ip=(Array.isArray(xf)?xf[0]:(xf||'')).split(',')[0].trim()||req.ip||'0.0.0.0'; return ip }
const hashIp = (ip, salt = process.env.IP_SALT || process.env.IP_HASH_SECRET || '') => createHash('sha256').update(String(salt)).update(String(ip)).digest('hex').slice(0, 32)

const FREECFG={ sizeCap:num(FREE_MAX_UPLOAD_MB)*MB, ttlDefaultDays:num(FREE_LINK_TTL_DEFAULT_DAYS), ttlMaxDays:num(FREE_LINK_TTL_MAX_DAYS), maxLinks30d:num(FREE_MAX_LINKS_PER_30D) }
const PROCFG={ capBytesPerPeriod:num(PRO_MAX_PERIOD_GB)*1024*1024*1024, ttlDays:num(PRO_LINK_TTL_DAYS) }
const PMCFG={ ttlDays:num(PROMAX_LINK_TTL_DAYS) }

// ---------- DB init (no FKs) + cols de plan ----------
async function initDb(){
  await pool.query(`CREATE EXTENSION IF NOT EXISTS "pgcrypto";`)
  await pool.query(`CREATE EXTENSION IF NOT EXISTS "uuid-ossp";`)

  const q = await pool.query(`SELECT data_type FROM information_schema.columns WHERE table_schema='public' AND table_name='users' AND column_name='id' LIMIT 1`)
  let usersIdType = q.rows[0]?.data_type
  if(!usersIdType){
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        email TEXT UNIQUE,
        phone TEXT UNIQUE,
        plan  TEXT NOT NULL DEFAULT 'FREE',
        plan_expires_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
    `)
    usersIdType='uuid'
  } else {
    // añade columnas si faltan
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS plan TEXT NOT NULL DEFAULT 'FREE'`)
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS plan_expires_at TIMESTAMPTZ`)
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now()`)
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now()`)
  }
  const USER_ID_SQLTYPE = (usersIdType==='bigint')?'BIGINT':'UUID'

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
    );`)

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
    );`)

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
    );`)

  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS idx_links_key_unique ON links(key);`)
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_links_user_created ON links(user_id, created_at DESC);`)
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_links_anon_created ON links(anon_ip, created_at DESC);`)
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_links_expires ON links(expires_at);`)
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_pkg_created ON packages(created_at DESC);`)
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_pkg_items_pkg ON package_items(package_id);`)

  console.log('[DB] ready (no-FK, users.plan + plan_expires_at)')
}

// ---------- app ----------
const app = express()
app.set('trust proxy', true)
app.get('/', (_req,res)=> res.json({ ok:true, name:'MixtliTransfer3000', docs:'/api/health', time:new Date().toISOString() }))
app.use(cors({ origin:(o,cb)=>{ if(!o) return cb(null,true); if(SEALED.ALLOWED_ORIGINS.includes(o)) return cb(null,true); cb(new Error('origin_not_allowed')); }, methods:['GET','POST','OPTIONS'], allowedHeaders:['Content-Type','Authorization','x-mixtli-token'] }))
app.use(express.json({ limit:'2mb' }))
app.get('/api/health', (_req,res)=> res.json({ ok:true, service:'mixtlitransfer3000', time:new Date().toISOString() }))

// ---------- auth-lite OTP ----------
const otpStore=new Map()
function setOtp(key){ const code=String(Math.floor(100000+Math.random()*900000)); const exp=Date.now()+Number(OTP_TTL_MIN)*60*1000; otpStore.set(key,{code,exp}); console.log('[OTP]',key,code) }
function verifyOtp(key, code){ const row=otpStore.get(key); if(!row) return false; if(Date.now()>row.exp){ otpStore.delete(key); return false } const ok=row.code===String(code); if(ok) otpStore.delete(key); return ok }
function signToken(user){ return jwt.sign({ uid:user.id, plan:user.plan }, JWT_SECRET, { expiresIn:'30d' }) }
async function ensureFreshPlan(userId){
  const { rows } = await pool.query(`UPDATE users SET plan='FREE' WHERE id=$1 AND plan_expires_at IS NOT NULL AND plan_expires_at < now() RETURNING id`, [userId])
  return rows.length>0
}
async function authOptional(req,_res,next){ const a=req.headers.authorization||''; const t=a.startsWith('Bearer ')?a.slice(7):''; if(!t) return next(); try{ const p=jwt.verify(t,JWT_SECRET); await ensureFreshPlan(p.uid); const { rows }=await pool.query('SELECT id,email,phone,plan,plan_expires_at FROM users WHERE id=$1',[p.uid]); req.user=rows[0]||null }catch(_e){ req.user=null } finally{ next() } }
async function authRequired(req,res,next){ await authOptional(req,res,()=>{}); if(!req.user) return res.status(401).json({ error:'auth_required' }); next() }

app.post('/api/auth/register', async (req,res)=>{ const { email, phone }=req.body||{}; const id=(email&&String(email).toLowerCase())||(phone&&String(phone))||''; if(!id) return res.status(400).json({ error:'email_or_phone_required' }); setOtp(id); res.json({ ok:true, msg:'otp_sent' }) })
app.post('/api/auth/verify-otp', async (req,res)=>{ const { email, phone, otp }=req.body||{}; const id=(email&&String(email).toLowerCase())||(phone&&String(phone))||''; if(!id||!otp) return res.status(400).json({ error:'need_id_and_otp' }); if(!verifyOtp(id,otp)) return res.status(400).json({ error:'otp_invalid' }); const c=await pool.connect(); try{ await c.query('BEGIN'); let row; if(email){ const r=await c.query(`INSERT INTO users (email,plan) VALUES ($1,'FREE') ON CONFLICT (email) DO UPDATE SET updated_at=now() RETURNING id,email,phone,plan,plan_expires_at`,[email.toLowerCase()]); row=r.rows[0] } else { const r=await c.query(`INSERT INTO users (phone,plan) VALUES ($1,'FREE') ON CONFLICT (phone) DO UPDATE SET updated_at=now() RETURNING id,email,phone,plan,plan_expires_at`,[phone]); row=r.rows[0] } await c.query('COMMIT'); const token=signToken(row); res.json({ token, user:row }) } catch(e){ await c.query('ROLLBACK'); console.error(e); res.status(500).json({ error:'verify_failed' }) } finally{ c.release() } })

// profile
app.get('/api/me', authRequired, async (req,res)=>{
  res.json({ user: req.user })
})

// upgrade/downgrade
app.post('/api/plan/upgrade', authRequired, async (req,res)=>{
  try{
    const plan = String(req.body?.plan||'').toUpperCase()
    if(!['PRO','PROMAX'].includes(plan)) return res.status(400).json({ error:'invalid_plan' })
    const days = (plan==='PROMAX') ? num(process.env.PROMAX_PERIOD_DAYS||'30') : num(process.env.PRO_PERIOD_DAYS||'30')
    const { rows } = await pool.query(`UPDATE users SET plan=$1, plan_expires_at = now() + ($2||' days')::interval, updated_at=now() WHERE id=$3 RETURNING id,email,plan,plan_expires_at`, [plan, days, req.user.id])
    const user = rows[0]
    res.json({ ok:true, user })
  }catch(e){ console.error(e); res.status(500).json({ error:'upgrade_failed' }) }
})
app.post('/api/plan/downgrade', authRequired, async (req,res)=>{
  try{
    const { rows } = await pool.query(`UPDATE users SET plan='FREE', plan_expires_at=NULL, updated_at=now() WHERE id=$1 RETURNING id,email,plan,plan_expires_at`, [req.user.id])
    res.json({ ok:true, user: rows[0] })
  }catch(e){ console.error(e); res.status(500).json({ error:'downgrade_failed' }) }
})

// ---------- presign (igual que v2.1, con verificación de límites) ----------
const FREECFG2=FREECFG
app.post('/api/presign', authOptional, async (req,res)=>{
  try{
    const user=req.user
    let { filename, contentType, contentLength, plan, durationDays } = req.body||{}
    filename=String(filename||''); contentType=String(contentType||'application/octet-stream'); contentLength=Number(contentLength||0); plan=String(plan||(user?.plan||'FREE')).toUpperCase()

    // aplicar plan actual (si expiró, se habrá bajado a FREE en authOptional)
    if(user && plan!==(user.plan||'FREE')) plan = user.plan||'FREE'

    const ttlDays = plan==='PRO'? PROCFG.ttlDays : (plan==='PROMAX'? PMCFG.ttlDays : clamp(num(durationDays||FREECFG2.ttlDefaultDays), FREECFG2.ttlDefaultDays, FREECFG2.ttlMaxDays))

    if(plan==='FREE' && !user){
      if (!filename || !contentType || !contentLength) return res.status(400).json({ error:'bad_params' })
      if (contentLength > FREECFG2.sizeCap) return res.status(413).json({ error:'file_too_large', maxBytes: FREECFG2.sizeCap })
      const anon=hashIp(clientIp(req))
      const { rows }=await pool.query(`SELECT COUNT(*)::int AS cnt FROM links WHERE anon_ip=$1 AND created_at>= now()-INTERVAL '30 days'`,[anon])
      if(Number(rows[0]?.cnt||0) >= FREECFG2.maxLinks30d) return res.status(429).json({ error:'free_link_count_exceeded', limit: FREECFG2.maxLinks30d })
      const ext=extOf(filename); const day=new Date().toISOString().slice(0,10); const key=`mt/FREE/${day}/${randomUUID()}${ext?'.'+ext:''}`
      await pool.query(`INSERT INTO links (user_id,anon_ip,plan,key,filename,content_type,size_bytes,expires_at,active) VALUES (NULL,$1,'FREE',$2,$3,$4,$5, now()+($6||' days')::interval, true)`,[anon,key,filename,contentType,contentLength,ttlDays])
      const put=new PutObjectCommand({ Bucket:SEALED.S3_BUCKET, Key:key, ContentType:contentType, Metadata:{'x-plan':'FREE','x-origin':'mixtli'} })
      const uploadUrl=await getSignedUrl(s3,put,{expiresIn:num(UPLOAD_URL_TTL_SECONDS)})
      const get=new GetObjectCommand({ Bucket:SEALED.S3_BUCKET, Key:key, ResponseContentDisposition:`attachment; filename="${filename}"` })
      const downloadUrl=await getSignedUrl(s3,get,{expiresIn:num(DOWNLOAD_URL_TTL_SECONDS_MAX)})
      return res.json({ key, uploadUrl, uploadHeaders:{'Content-Type':contentType}, downloadUrl, expiresInSeconds: ttlDays*24*3600 })
    }

    if(!user) return res.status(401).json({ error:'auth_required' })

    // cuotas por usuario (últimos 30d, similar v2.1)
    const { rows:agg }=await pool.query(`SELECT COALESCE(SUM(size_bytes),0) AS bytes, COUNT(*) AS count FROM links WHERE user_id=$1 AND created_at>= now()-INTERVAL '30 days'`,[user.id])
    const usedBytes=Number(agg[0].bytes||0)

    if(plan==='PRO'){ if(usedBytes+contentLength>PROCFG.capBytesPerPeriod) return res.status(429).json({ error:'pro_bytes_quota_exceeded', limitBytes: PROCFG.capBytesPerPeriod, usedBytes }) }
    if(plan==='FREE'){ if(contentLength>FREECFG2.sizeCap) return res.status(413).json({ error:'file_too_large', maxBytes: FREECFG2.sizeCap }) }

    if (!filename || !contentType || !contentLength) return res.status(400).json({ error:'bad_params' })

    const ext=extOf(filename); const day=new Date().toISOString().slice(0,10); const key=`mt/${plan}/${day}/${randomUUID()}${ext?'.'+ext:''}`
    await pool.query(`INSERT INTO links (user_id,plan,key,filename,content_type,size_bytes,expires_at,active) VALUES ($1,$2,$3,$4,$5,$6, now()+($7||' days')::interval, true)`,[user.id,plan,key,filename,contentType,contentLength,ttlDays])

    const put=new PutObjectCommand({ Bucket:SEALED.S3_BUCKET, Key:key, ContentType:contentType, Metadata:{'x-plan':plan,'x-origin':'mixtli'} })
    const uploadUrl=await getSignedUrl(s3,put,{expiresIn:num(UPLOAD_URL_TTL_SECONDS)})
    const get=new GetObjectCommand({ Bucket:SEALED.S3_BUCKET, Key:key, ResponseContentDisposition:`attachment; filename="${filename}"` })
    const downloadUrl=await getSignedUrl(s3,get,{expiresIn:num(DOWNLOAD_URL_TTL_SECONDS_MAX)})

    res.json({ key, uploadUrl, uploadHeaders:{'Content-Type':contentType}, downloadUrl, expiresInSeconds: ttlDays*24*3600 })
  }catch(e){ console.error(e); res.status(500).json({ error:'presign_failed', detail:String(e) }) }
})

// ---------- packages igual que v2.1.3 (omitidos por brevedad) ----------
// (Para demo centrada en upgrade, puedes seguir usando endpoints de package si ya los tenías en 2.1.3)

await initDb()
app.listen(PORT, ()=> console.log('MixtliTransfer3000 v2.2.0 on :' + PORT))
