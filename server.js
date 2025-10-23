/**
 * Mixtli Transfer 3000 — Backend v2.3.4
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

/* ----------------------- VARS: R2 ó S3 (compat) ----------------------- */
// Acepta tanto R2_* como S3_*. Si S3_* no están, toma de R2_*.
const S3_ENDPOINT =
  process.env.S3_ENDPOINT || process.env.R2_ENDPOINT; // ej: https://xxxx.r2.cloudflarestorage.com
const S3_BUCKET =
  process.env.S3_BUCKET || process.env.R2_BUCKET;
const S3_ACCESS_KEY_ID =
  process.env.S3_ACCESS_KEY_ID || process.env.R2_ACCESS_KEY_ID;
const S3_SECRET_ACCESS_KEY =
  process.env.S3_SECRET_ACCESS_KEY || process.env.R2_SECRET_ACCESS_KEY;

// Normaliza endpoint (sin slash final)
const ENDPOINT = (S3_ENDPOINT || '').replace(/\/+$/, '');

/* ----------------------------- CORS ----------------------------------- */
function parseAllowedOrigins() {
  try {
    const raw = process.env.ALLOWED_ORIGINS;
    if (!raw) return [];
    const arr = JSON.parse(raw);
    return Array.isArray(arr) ? arr : [];
  } catch {
    console.error('ALLOWED_ORIGINS mal formateado. Usa JSON, ej. ["https://tu-dominio"]');
    return [];
  }
}
const ALLOWED = parseAllowedOrigins();

app.use(cors({
  origin(origin, cb) {
    // Permitir sin Origin (curl/SSR/Render health)
    if (!origin) return cb(null, true);
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

/* ---------------------------- S3 / R2 --------------------------------- */
// Forzar SigV4 (R2 NO soporta SigV2). Path-style recomendado.
const s3 = new AWS.S3({
  accessKeyId: S3_ACCESS_KEY_ID,
  secretAccessKey: S3_SECRET_ACCESS_KEY,
  endpoint: ENDPOINT,               // string ok para SDK v2
  signatureVersion: 'v4',           // <- OBLIGATORIO en R2
  s3ForcePathStyle: true,           // recomendado para R2
  region: process.env.S3_REGION || 'auto'
});

const BUCKET = S3_BUCKET;

/* ---------------------------- HEALTH ---------------------------------- */
app.get(['/salud', '/api/health'], (req, res) => {
  res.json({
    ok: true,
    bucket: BUCKET,
    endpoint: ENDPOINT,
    time: new Date().toISOString()
  });
});

/* --------------------------- PRESIGN API -------------------------------
 * POST /api/presign
 * body: { files: [{name, size, type}], expiresSeconds? }
 * return: { ok, results: [{ key, putUrl, getUrl, objectUrl, expiresSeconds }] }
 ----------------------------------------------------------------------- */
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

      // Firma PUT (subida) — Debe coincidir Content-Type con el que enviará el cliente
      const putUrl = await s3.getSignedUrlPromise('putObject', {
        Bucket: BUCKET,
        Key: key,
        ContentType: contentType,
        Expires: exp
      });

      // Firma GET (descarga) — 24h máx recomendado
      const getUrl = await s3.getSignedUrlPromise('getObject', {
        Bucket: BUCKET,
        Key: key,
        Expires: Math.min(exp, 60 * 60 * 24)
      });

      // URL “cruda” del objeto (NO pública salvo que abras el bucket)
      const objectUrl = `${ENDPOINT}/${BUCKET}/${encodeURIComponent(key)}`;

      return { key, putUrl, getUrl, objectUrl, expiresSeconds: exp };
    }));

    res.json({ ok: true, results });
  } catch (e) {
    console.error('presign error:', e);
    res.status(500).json({ ok: false, error: 'error al generar presign' });
  }
});

/* -------------------------- LISTADO SIMPLE ---------------------------- */
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

/* ------------------------------ BOOT ---------------------------------- */
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log('Mixtli Transfer 3000 v2.3.4 listening on', PORT);
});
