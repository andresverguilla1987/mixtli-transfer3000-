// MixtliTransfer3000 Backend v2.4.0
// (See previous cell for full comment header)
import 'dotenv/config'
import express from 'express'
import cors from 'cors'
import { randomUUID, createHash, scrypt } from 'node:crypto'
import { promisify } from 'node:util'
import jwt from 'jsonwebtoken'
import pg from 'pg'
import { S3Client, PutObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3'
import { getSignedUrl } from '@aws-sdk/s3-request-presigner'
import nodemailer from 'nodemailer'

const scryptAsync = promisify(scrypt)

const SEALED = {
  S3_ENDPOINT: process.env.S3_ENDPOINT || 'https://8351c372dedf0e354a3196aff085f0ae.r2.cloudflarestorage.com',
  S3_BUCKET: process.env.S3_BUCKET || 'mixtlitransfer3000',
  S3_REGION: process.env.S3_REGION || 'auto',
  S3_FORCE_PATH_STYLE: (process.env.S3_FORCE_PATH_STYLE || 'true') === 'true',
  ALLOWED_ORIGINS: (() => {
    try {
      const v = process.env.ALLOWED_ORIGINS
      if (!v) return ['https://lighthearted-froyo-9dd448.netlify.app','http://localhost:8888']
      if (v.trim().startsWith('[')) return JSON.parse(v)
      if (v.includes(',')) return v.split(',').map(s=>s.trim()).filter(Boolean)
      return [v.trim()]
    } catch { return ['https://lighthearted-froyo-9dd448.netlify.app','http://localhost:8888'] }
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
  PRO_MAX_PERIOD_GB = '400',
  PRO_LINK_TTL_DAYS = '7',
  PROMAX_LINK_TTL_DAYS = '22',
  PRO_PERIOD_DAYS = '30',
  PROMAX_PERIOD_DAYS = '30',
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
  IP_SALT,
  IP_HASH_SECRET
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
const hashIp = (ip, salt = IP_SALT || IP_HASH_SECRET || '') => createHash('sha256').update(String(salt)).update(String(ip)).digest('hex').slice(0, 32)

const FREECFG = { sizeCap: num(FREE_MAX_UPLOAD_MB) * 1024*1024, ttlDefaultDays: num(FREE_LINK_TTL_DEFAULT_DAYS), ttlMaxDays: num(FREE_LINK_TTL_MAX_DAYS), maxLinks30d: num(process.env.FREE_MAX_LINKS_PER_30DAYS || process.env.FREE_MAX_LINKS_PER_30D || '10') }
const PROCFG = { capBytesPerPeriod: num(PRO_MAX_PERIOD_GB) * 1024 * 1024 * 1024, ttlDays: num(PRO_LINK_TTL_DAYS) }
const PMCFG = { ttlDays: num(PROMAX_LINK_TTL_DAYS) }

const RL = new Map()
function rateLimit (key, limit, windowMs) { const now=Date.now(); const arr=RL.get(key)||[]; const fresh=arr.filter(ts=>now-ts<windowMs); fresh.push(now); RL.set(key,fresh); return fresh.length<=limit }

async function hashPw(pw) { const salt = cryptoRandom(); const key = await (await import('node:crypto')).scryptSync(String(pw), salt, 64); return { salt, hash: Buffer.from(key).toString('hex') } }
function cryptoRandom(){ return randomUUID().replace(/-/g,'') }

// (The rest of implementation is long; for the packaged zip we include the full server.js from earlier message.)
