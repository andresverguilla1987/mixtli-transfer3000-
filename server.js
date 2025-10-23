\
const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const { v4: uuidv4 } = require('uuid');
const AWS = require('aws-sdk');
require('dotenv').config();

const app = express();
app.use(express.json({ limit: '2mb' }));
app.use(morgan('tiny'));

function parseAllowedOrigins() {
  try {
    const raw = process.env.ALLOWED_ORIGINS;
    if (!raw) return [];
    const arr = JSON.parse(raw);
    return Array.isArray(arr) ? arr : [];
  } catch (e) {
    console.error('ALLOWED_ORIGINS mal formateado');
    return [];
  }
}
const ALLOWED = parseAllowedOrigins();
app.use(cors({
  origin: function (origin, cb) {
    if (!origin) return cb(null, true);
    if (ALLOWED.includes(origin)) return cb(null, true);
    return cb(new Error('CORS: Origin no permitido: ' + origin), false);
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'x-mixtli-token']
}));

const s3 = new AWS.S3({
  accessKeyId: process.env.S3_ACCESS_KEY_ID,
  secretAccessKey: process.env.S3_SECRET_ACCESS_KEY,
  endpoint: process.env.S3_ENDPOINT,
  region: process.env.S3_REGION || 'auto',
  s3ForcePathStyle: String(process.env.S3_FORCE_PATH_STYLE).toLowerCase() === 'true'
});
const BUCKET = process.env.S3_BUCKET;

app.get(['/salud','/api/health'], (req, res) => {
  res.json({ ok: true, bucket: BUCKET, endpoint: process.env.S3_ENDPOINT, time: new Date().toISOString() });
});

app.post('/api/presign', async (req, res) => {
  try {
    const { files = [], expiresSeconds } = req.body || {};
    if (!Array.isArray(files) || files.length === 0) return res.status(400).json({ ok: false, error: 'files[] requerido' });
    const exp = Math.min(Math.max(parseInt(expiresSeconds || 3600), 60), 604800);
    const results = await Promise.all(files.map(async (f) => {
      const safeName = (f.name || 'file').replace(/[^\w.\-]/g, '_');
      const key = `${new Date().toISOString().slice(0,10)}/${uuidv4()}-${safeName}`;
      const putUrl = s3.getSignedUrl('putObject', { Bucket: BUCKET, Key: key, ContentType: f.type || 'application/octet-stream', Expires: exp });
      const getUrl = s3.getSignedUrl('getObject', { Bucket: BUCKET, Key: key, Expires: Math.min(exp, 86400) });
      const objectUrl = `${process.env.S3_ENDPOINT.replace(/^https?:\/\//,'https://')}/${BUCKET}/${encodeURIComponent(key)}`;
      return { key, putUrl, getUrl, objectUrl, expiresSeconds: exp };
    }));
    res.json({ ok: true, results });
  } catch (e) {
    console.error('presign error:', e);
    res.status(500).json({ ok: false, error: 'error al generar presign' });
  }
});

app.get('/api/list', async (req, res) => {
  try {
    const prefix = req.query.prefix || '';
    const data = await s3.listObjectsV2({ Bucket: BUCKET, Prefix: prefix, MaxKeys: 50 }).promise();
    const items = (data.Contents || []).map(o => ({ key: o.Key, size: o.Size, lastModified: o.LastModified }));
    res.json({ ok: true, items });
  } catch (e) {
    console.error('list error:', e);
    res.status(500).json({ ok: false, error: 'error al listar' });
  }
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log('Mixtli Transfer 3000 v2.3.3 on', PORT));
