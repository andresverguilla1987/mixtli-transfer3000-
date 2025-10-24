# MixtliTransfer3000 — Backend (Transfer Puro)

**Stack:** Node.js (Express) + AWS SDK v3 (S3-compatible, Cloudflare R2).  
**DB-less:** No database; download links are signed GET URLs that expire after `LINK_TTL_HOURS`.

## Endpoints
- `GET /api/health` → quick check
- `POST /api/presign` → body: `{ filename, contentType, contentLength }` → returns `{ key, uploadUrl, uploadHeaders, downloadUrl, expiresInSeconds }`

## Deploy (Render)
1. Create a new **Web Service** → Node 18+.
2. Build command:  
   ```
   npm install --omit=dev --no-audit --no-fund
   ```
3. Start command:  
   ```
   node server.js
   ```
4. Set env vars as in `.env.example`.
5. Open `https://<your-service>.onrender.com/api/health`.

## CORS
Set `ALLOWED_ORIGINS` to a JSON array containing your Netlify origin(s).

## Notes
- Upload URL expires in 1 hour (enough to PUT large files).
- Download URL expires after `LINK_TTL_HOURS` (default 72h).
- `MAX_UPLOAD_MB` is a policy check; uploads go direct to R2.
