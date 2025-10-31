# Mixtli Backend v2.13r
Cambio: `/api/pack/create` devuelve **siempre** `"/share/:id"` (FORCE_RELATIVE_URLS=true).

## Variables Render
```
PORT=10000
DATABASE_URL=postgres://...
JWT_SECRET=supersecret
OTP_TTL_MIN=10

# Twilio SMS-only
TWILIO_ACCOUNT_SID=...
TWILIO_AUTH_TOKEN=...
TWILIO_FROM=+1XXXXXXXXXX

# R2 (sin bucket en endpoint)
S3_ENDPOINT=https://<account>.r2.cloudflarestorage.com
S3_BUCKET=mixtlitransfer3000
S3_REGION=auto
S3_ACCESS_KEY_ID=...
S3_SECRET_ACCESS_KEY=...
S3_FORCE_PATH_STYLE=true

# Forzar URL relativa del paquete
FORCE_RELATIVE_URLS=true
```

## Netlify _redirects (frontend)
```
/ api/health 200
/api/*     https://mixtli-transfer3000.onrender.com/:splat  200
/share/*   https://mixtli-transfer3000.onrender.com/share/:splat  200
/*         /index.html  200
```
