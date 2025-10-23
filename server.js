/**
 * Mixtli Transfer 3000 — Backend v2.4.0
 * Render + Cloudflare R2 (S3-compatible) + Netlify
 */
const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

/* AWS SDK v3 */
const { S3Client, GetObjectCommand, PutObjectCommand, ListObjectsV2Command } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');

const app = express();
app.use(express.json({ limit: '2mb' }));
app.use(morgan('tiny'));

/* ───────────── Vars: R2 / S3 ───────────── */
const S3_ENDPOINT = (process.env.S3_ENDPOINT || process.env.R2_ENDPOINT || '').replace(/\/+$/, '');
const S3_BUCKET   = process.env.S3_BUCKET || process.env.R2_BUCKET || '';
const S3_ACCESS_KEY_ID     = (process.env.S3_ACCESS_KEY_ID || process.env.R2_ACCESS_KEY_ID || '').trim();
const S3_SECRET_ACCESS_KEY = (process.env.S3_SECRET_ACCESS_KEY || process.env.R2_SECRET_ACCESS_KEY || '').trim();

if (!S3_ENDPOINT || !S3_BUCKET || !S3_ACCESS_KEY_ID || !S3_SECRET_ACCESS_KEY) {
  console.warn('[WARN] Variables S3/R2 incompletas. Revisa .env en Render.');
}

/* ───────────── CORS ───────────── */
function parseAllowedOrigins() {
  try {
    const raw = process.env.ALLOWED_ORIGINS;
    if (!raw) return [];
    const arr = JSON.parse(raw);
    return Array.isArray(arr) ? arr : [];
  } catch {
    console.error('ALLOWED_ORIGINS mal formateado. Usa JSON. Ej: ["https://tu-netlify.netlify.app"]');
    return [];
  }
}
const ALLOWED = parseAllowedOrigins();

app.use(cors({
  origin(origin, cb) {
    if (!origin) return cb(null, true);  // curl/SSR/health
    if (ALLOWED.includes(origin)) return cb(null, true);
    return cb(new Error('CORS: Origin no permitido: ' + origin), false);
  },
  methods: ['GET', 'POST', 'PUT', 'HEAD', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'x-mixtli-token',
    'authorization',
    'x-amz-acl',
    'x-amz-content-sha256',
    'x-amz-date',
    'x-amz-security-token'
  ]
}));

/* ───────────── S3 Client (R2) ─────────────
   - R2 requiere SigV4 y path-style
*/
const s3 = new S3Client({
  region: process.env.S3_REGION || 'auto',
  endpoint: S3_ENDPOINT,            // ej: https://xxxxxxxx.r2.cloudflarestorage.com
  forcePathStyle: true,
  credentials: {
    accessKeyId: S3_ACCESS_KEY_ID,
    secretAccessKey: S3_SECRET_ACCESS_KEY
  }
});

/* ───────────── Helpers ───────────── */
const BUCKET = S3_BUCKET;

function safeName(name) {
  return (name || 'file').replace(/[^\w.\-]/g, '_');
}
function objUrl(key) {
  return `${S3_ENDPOINT}/${BUCKET}/${encodeURIComponent(key)}`;
}

/* ───────────── Health ───────────── */
app.get(['/salud', '/api/health'], (req, res) => {
  res.json({ ok: true, bucket: BUCKET, endpoint: S3_ENDPOINT, time: new Date().toISOString() });
});

/* Debug: ver longitud de la accessKey para confirmar en Render */
app.get('/api/debug-cred', (req, res) => {
  const id = S3_ACCESS_KEY_ID || null;
  res.json({
    ok: true,
    accessKeyId_len: id ? id.length : 0,
    accessKeyId_preview: id ? `${id.slice(0, 4)}...${id.slice(-4)}` : null,
    endpoint: S3_ENDPOINT,
    bucket: BUCKET
  });
});

/* ───────────── Presign ─────────────
   body: { files: [{name, size, type}], expiresSeconds? }
*/
app.post('/api/presign', async (req, res) => {
  try {
    const { files = [], expiresSeconds } = req.body || {};
    if (!Array.isArray(files) || files.length === 0) {
      return res.status(400).json({ ok: false, error: 'files[] requerido' });
    }
    // 60s–7d
    const exp = Math.min(Math.max(parseInt(expiresSeconds || 3600, 10), 60), 60 * 60 * 24 * 7);

    const results = await Promise.all(files.map(async (f) => {
      const name = safeName(f.name);
      const key = `${new Date().toISOString().slice(0, 10)}/${uuidv4()}-${name}`;
      const contentType = f.type || 'application/octet-stream';

      // PUT
      const putCmd = new PutObjectCommand({ Bucket: BUCKET, Key: key, ContentType: contentType });
      const putUrl = await getSignedUrl(s3, putCmd, { expiresIn: exp });

      // GET (máx recomendado 24h)
      const getCmd = new GetObjectCommand({ Bucket: BUCKET, Key: key });
      const getUrl = await getSignedUrl(s3, getCmd, { expiresIn: Math.min(exp, 86400) });

      return {
        key,
        putUrl,
        getUrl,
        objectUrl: objUrl(key),
        expiresSeconds: exp
      };
    }));

    res.json({ ok: true, results });
  } catch (e) {
    console.error('presign error:', e);
    res.status(500).json({ ok: false, error: 'error al generar presign' });
  }
});

/* ───────────── Listado simple ───────────── */
app.get('/api/list', async (req, res) => {
  try {
    const prefix = req.query.prefix || '';
    const out = await s3.send(new ListObjectsV2Command({ Bucket: BUCKET, Prefix: prefix, MaxKeys: 50 }));
    const items = (out.Contents || []).map(o => ({
      key: o.Key,
      size: o.Size,
      lastModified: o.LastModified
    }));
    res.json({ ok: true, items });
  } catch (e) {
    console.error('list error:', e);
    res.status(500).json({ ok: false, error: 'error al listar' });
  }
});

/* ───────────── Boot ───────────── */
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log('Mixtli Transfer 3000 v2.4.0 listening on', PORT);
});
