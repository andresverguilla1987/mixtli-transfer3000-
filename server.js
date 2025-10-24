/**
 * Mixtli Transfer 3000 — Backend v2.5.0
 * Render + Cloudflare R2 (S3-compatible) + Netlify
 * + Métricas (uploads/downloads) y límite de descargas por archivo
 */

const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

/* AWS SDK v3 */
const {
  S3Client, GetObjectCommand, PutObjectCommand, ListObjectsV2Command
} = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');

/* Postgres (Render) */
const { Pool } = require('pg');

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

const s3 = new S3Client({
  region: process.env.S3_REGION || 'auto',
  endpoint: S3_ENDPOINT,
  forcePathStyle: true,
  credentials: {
    accessKeyId: S3_ACCESS_KEY_ID,
    secretAccessKey: S3_SECRET_ACCESS_KEY
  }
});

/* ───────────── Postgres ───────────── */
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS mixtli_stats (
      id           BIGSERIAL PRIMARY KEY,
      key          TEXT,
      event        TEXT,            -- 'upload' | 'download'
      size         BIGINT,
      ip           TEXT,
      created_at   TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS mixtli_links (
      id           BIGSERIAL PRIMARY KEY,
      key          TEXT UNIQUE,     -- mismo key que usas para el objeto
      max_downloads INT DEFAULT 10, -- límite por archivo
      downloads     INT DEFAULT 0,  -- contador actual
      expires_at    TIMESTAMP NULL  -- opcional: fecha de expiración
    );
  `);
  console.log('DB OK (mixtli_stats, mixtli_links)');
}
initDb().catch(err => console.error('initDb error', err));

/* ───────────── Helpers ───────────── */
function safeName(name) {
  return (name || 'file').replace(/[^\w.\-]/g, '_');
}
function objUrl(key) {
  return `${S3_ENDPOINT}/${S3_BUCKET}/${encodeURIComponent(key)}`;
}
function clientIp(req) {
  return (req.headers['x-forwarded-for'] || req.ip || '').toString().split(',')[0].trim();
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

/* ───────────── Health / Debug ───────────── */
app.get(['/salud', '/api/health'], (req, res) => {
  res.json({ ok: true, bucket: S3_BUCKET, endpoint: S3_ENDPOINT, time: new Date().toISOString() });
});

app.get('/api/debug-cred', (req, res) => {
  const id = S3_ACCESS_KEY_ID || null;
  res.json({
    ok: true,
    accessKeyId_len: id ? id.length : 0,
    accessKeyId_preview: id ? `${id.slice(0, 4)}...${id.slice(-4)}` : null,
    endpoint: S3_ENDPOINT,
    bucket: S3_BUCKET
  });
});

/* ───────────── Presign (sin cambios para el FE) ───────────── */
app.post('/api/presign', async (req, res) => {
  try {
    const { files = [], expiresSeconds, maxDownloads } = req.body || {};
    if (!Array.isArray(files) || files.length === 0) {
      return res.status(400).json({ ok: false, error: 'files[] requerido' });
    }
    const exp = Math.min(Math.max(parseInt(expiresSeconds || 3600, 10), 60), 60 * 60 * 24 * 7);
    const defaultMax = Number.isInteger(maxDownloads) ? maxDownloads : 10; // default 10 descargas

    const results = await Promise.all(files.map(async (f) => {
      const name = safeName(f.name);
      const key = `${new Date().toISOString().slice(0, 10)}/${uuidv4()}-${name}`;
      const contentType = f.type || 'application/octet-stream';

      const putCmd = new PutObjectCommand({ Bucket: S3_BUCKET, Key: key, ContentType: contentType });
      const putUrl = await getSignedUrl(s3, putCmd, { expiresIn: exp });

      const getCmd = new GetObjectCommand({ Bucket: S3_BUCKET, Key: key });
      const getUrl = await getSignedUrl(s3, getCmd, { expiresIn: Math.min(exp, 86400) });

      // crea/asegura entrada para límites
      await pool.query(
        `INSERT INTO mixtli_links (key, max_downloads, downloads)
         VALUES ($1, $2, 0)
         ON CONFLICT (key) DO NOTHING`,
        [key, defaultMax]
      );

      // registra "upload" en stats
      const size = parseInt(f.size || 0, 10) || null;
      await pool.query(
        `INSERT INTO mixtli_stats (key, event, size, ip) VALUES ($1, 'upload', $2, $3)`,
        [key, size, clientIp(req)]
      );

      return {
        key,
        putUrl,
        getUrl,              // presign directo (24h) si quieres continuar como antes
        objectUrl: objUrl(key),
        expiresSeconds: exp,
        maxDownloads: defaultMax,
        downloadPage: `${process.env.PUBLIC_BASE_URL || ''}/d/${encodeURIComponent(key)}` // landing de descarga
      };
    }));

    res.json({ ok: true, results });
  } catch (e) {
    console.error('presign error:', e);
    res.status(500).json({ ok: false, error: 'error al generar presign' });
  }
});

/**
 * GET /api/dl/:key
 * - Verifica el límite de descargas en mixtli_links
 * - Si permite: incrementa contador, registra en mixtli_stats y redirige al GET presign
 * - Si no: responde 410 (Gone) con mensaje
 */
app.get('/api/dl/:key', async (req, res) => {
  try {
    const key = decodeURIComponent(req.params.key || '').trim();
    if (!key) return res.status(400).json({ ok: false, error: 'key requerido' });

    const { rows } = await pool.query('SELECT * FROM mixtli_links WHERE key = $1', [key]);
    if (rows.length === 0) {
      return res.status(404).json({ ok: false, error: 'archivo no encontrado (link)' });
    }
    const row = rows[0];

    // expiración (opcional)
    if (row.expires_at && new Date(row.expires_at) < new Date()) {
      return res.status(410).json({ ok: false, error: 'archivo expirado' });
    }

    if (row.downloads >= row.max_downloads) {
      return res.status(410).json({ ok: false, error: 'límite de descargas alcanzado' });
    }

    // genera presign GET al vuelo
    const getCmd = new GetObjectCommand({ Bucket: S3_BUCKET, Key: key });
    const presignGet = await getSignedUrl(s3, getCmd, { expiresIn: 60 * 10 }); // 10 min

    // incrementa contador y guarda stat
    await pool.query('UPDATE mixtli_links SET downloads = downloads + 1 WHERE key = $1', [key]);
    await pool.query(
      `INSERT INTO mixtli_stats (key, event, ip) VALUES ($1, 'download', $2)`,
      [key, clientIp(req)]
    );

    // redirige al archivo
    res.json({ ok: true, redirect: presignGet });
  } catch (e) {
    console.error('dl error:', e);
    res.status(500).json({ ok: false, error: 'error en descarga' });
  }
});

/**
 * GET /api/stats/report?days=7
 * - Resumen simple por día (uploads / downloads)
 */
app.get('/api/stats/report', async (req, res) => {
  try {
    const days = Math.max(parseInt(req.query.days || '7', 10), 1);
    const { rows } = await pool.query(
      `
      with range as (
        select generate_series::date as day
        from generate_series(now()::date - ($1::int - 1) * interval '1 day', now()::date, interval '1 day')
      )
      select
        r.day,
        coalesce(u.cnt, 0) as uploads,
        coalesce(d.cnt, 0) as downloads
      from range r
      left join (
        select date(created_at) d, count(*) cnt
        from mixtli_stats where event='upload'
        group by 1
      ) u on u.d = r.day
      left join (
        select date(created_at) d, count(*) cnt
        from mixtli_stats where event='download'
        group by 1
      ) d on d.d = r.day
      order by r.day asc
      `,
      [days]
    );
    res.json({ ok: true, days, data: rows });
  } catch (e) {
    console.error('report error:', e);
    res.status(500).json({ ok: false, error: 'error en reporte' });
  }
});

/* ───────────── Listado simple (igual que antes) ───────────── */
app.get('/api/list', async (req, res) => {
  try {
    const prefix = req.query.prefix || '';
    const out = await s3.send(new ListObjectsV2Command({ Bucket: S3_BUCKET, Prefix: prefix, MaxKeys: 50 }));
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
  console.log('Mixtli Transfer 3000 v2.5.0 listening on', PORT);
});
