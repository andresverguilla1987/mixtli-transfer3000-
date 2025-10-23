/**
 * Mixtli Transfer 3000 — Backend v2.3.5
 * Render + Cloudflare R2 (S3-compatible) + Netlify
 */
const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const { v4: uuidv4 } = require('uuid');
const AWS = require('aws-sdk');
require('dotenv').config();

const app = express();
app.use(express.json({ limit: '2mb' }));
app.use(morgan('tiny'));

/* ───────────────── Vars: R2 ó S3 (compat) ───────────────── */
const S3_ENDPOINT =
  process.env.S3_ENDPOINT || process.env.R2_ENDPOINT; // p.ej. https://xxxx.r2.cloudflarestorage.com
const S3_BUCKET =
  process.env.S3_BUCKET || process.env.R2_BUCKET;
const S3_ACCESS_KEY_ID =
  (process.env.S3_ACCESS_KEY_ID || process.env.R2_ACCESS_KEY_ID || '').trim();
const S3_SECRET_ACCESS_KEY =
  (process.env.S3_SECRET_ACCESS_KEY || process.env.R2_SECRET_ACCESS_KEY || '').trim();

// Normaliza endpoint (sin slash final)
const ENDPOINT = (S3_ENDPOINT || '').replace(/\/+$/, '');

// Pequeña validación (no bloquea, solo advierte en logs)
if (!S3_ACCESS_KEY_ID || !S3_SECRET_ACCESS_KEY || !ENDPOINT || !S3_BUCKET) {
  console.warn('[WARN] Variables S3/R2 incompletas. Revisa .env en Render.');
}

/* ─────────────────────────── CORS ────────────────────────── */
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
    if (!origin) return cb(null, true);           // curl/SSR/health
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

/* ───────────────────────── S3 / R2 ──────────────────────── */
// R2 exige SigV4 y path-style
const s3 = new AWS.S3({
  accessKeyId: S3_ACCESS_KEY_ID,
  secretAccessKey: S3_SECRET_ACCESS_KEY,
  endpoint: ENDPOINT,
  signatureVersion: 'v4',
  s3ForcePathStyle: true,
  region: process.env.S3_REGION || 'auto'
});

const BUCKET = S3_BUCKET;

/* ─────────────────────────── Health ─────────────────────── */
app.get(['/salud', '/api/health'], (req, res) => {
  res.json({
    ok: true,
    bucket: BUCKET,
    endpoint: ENDPOINT,
    time: new Date().toISOString()
  });
});

/* Debug: confirmar que Render tiene las creds correctas (longitud y preview) */
app.get('/api/debug-cred', (req, res) => {
  const id = S3_ACCESS_KEY_ID || null;
  res.json({
    ok: true,
    accessKeyId_len: id ? id.length : 0,
    accessKeyId_preview: id ? `${id.slice(0, 4)}...${id.slice(-4)}` : null,
    endpoint: ENDPOINT,
    bucket: BUCKET
  });
});

/* ──────────────────────── Presign API ──────────────────────
 * POST /api/presign
 * body: { files: [{name, size, type}], expiresSeconds? }
 * return: { ok, results: [{ key, putUrl, getUrl, objectUrl, expiresSeconds }] }
 * ─────────────────────────────────────────────────────────── */
app.post('/api/presign', async (req, res) => {
  try {
    const { files = [], expiresSeconds } = req.body || {};
    if (!Array.isArray(files) || files.length === 0) {
      return res.status(400).json({ ok: false, error: 'files[] requerido' });
    }

    // Expiración: 60s – 7 días
    const exp = Math.min(Math.max(parseInt(expiresSeconds || 3600, 10), 60), 60 * 60 * 24 * 7);

    const results = await Promise.all(files.map(async (f) => {
      const safeName = (f.name || 'file').replace(/[^\w.\-]/g, '_');
      const key = `${new Date().toISOString().slice(0, 10)}/${uuidv4()}-${safeName}`;
      const contentType = f.type || 'application/octet-stream';

      // PUT presign — ContentType debe coincidir con lo que enviará el cliente
      const putUrl = await s3.getSignedUrlPromise('putObject', {
        Bucket: BUCKET,
        Key: key,
        ContentType: contentType,
        Expires: exp
      });

      // GET presign — 24h recomendado
      const getUrl = await s3.getSignedUrlPromise('getObject', {
        Bucket: BUCKET,
        Key: key,
        Expires: Math.min(exp, 60 * 60 * 24)
      });

      // URL "cruda" (no pública salvo que abras el bucket)
      const objectUrl = `${ENDPOINT}/${BUCKET}/${encodeURIComponent(key)}`;

      return { key, putUrl, getUrl, objectUrl, expiresSeconds: exp };
    }));

    res.json({ ok: true, results });
  } catch (e) {
    console.error('presign error:', e);
    res.status(500).json({ ok: false, error: 'error al generar presign' });
  }
});

/* ─────────────────────── Listado simple ─────────────────── */
app.get('/api/list', async (req, res) => {
  try {
    const prefix = req.query.prefix || '';
    const data = await s3.listObjectsV2({ Bucket: BUCKET, Prefix: prefix, MaxKeys: 50 }).promise();
    const items = (data.Contents || []).map(o => ({
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

/* ─────────────────────────── Boot ───────────────────────── */
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log('Mixtli Transfer 3000 v2.3.5 listening on', PORT);
});
