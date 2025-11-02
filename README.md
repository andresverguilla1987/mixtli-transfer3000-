# Mixtli Transfer — Kit Netlify + Backend (v2.14.4-lock)

Candado activado, rutas proxyeadas y descarga ZIP directa desde Render.

## 0) Requisitos
- **Backend (Render)**: Node 18+, Postgres, Cloudflare R2 (S3 compatible).
- **Frontend (Netlify)**: publicar carpeta `public/` de este kit.

## 1) Variables de entorno (Render)
Crea estas env vars en Render (o usa el archivo `.env` si corres local):

```env
NODE_ENV=production
PORT=10000
DATABASE_URL=postgres://user:pass@host:5432/db
JWT_SECRET=pon_un_token_bien_largo
OTP_TTL_MIN=10

# CORS
ALLOWED_ORIGINS=["https://<TU_NETLIFY>.netlify.app"]

# R2 / S3
S3_ENDPOINT=https://<account>.r2.cloudflarestorage.com
S3_BUCKET=mixtlitransfer
S3_REGION=auto
S3_ACCESS_KEY_ID=xxxxxxxx
S3_SECRET_ACCESS_KEY=xxxxxxxx
S3_FORCE_PATH_STYLE=true

# IMPORTANTÍSIMA (para ZIP directo, evita ERR_INVALID_RESPONSE)
BACKEND_PUBLIC_ORIGIN=https://<tu-backend>.onrender.com

# Opcionales
PUBLIC_BASE_URL=
CONTENT_DISPOSITION=attachment

# Twilio (SMS-only) o Email (SendGrid/SMTP)
TWILIO_ACCOUNT_SID=
TWILIO_AUTH_TOKEN=
TWILIO_FROM=+1xxxxxxxxxx

SENDGRID_API_KEY=
SENDGRID_FROM=
SMTP_HOST=
SMTP_PORT=587
SMTP_USER=
SMTP_PASS=
SMTP_FROM=

# Diagnóstico solo-lectura
CONFIG_DIAG_TOKEN=solo-lectura-diag
```

> **Candado**: el servidor hace `assertEnv()` al inicio y aborta si falta algo crítico o si `ALLOWED_ORIGINS` no es un JSON array **no vacío**.

## 2) Backend (Render)
- Start: `node server.js`
- Node: `18+` (ideal 18/20).
- Postgres: SSL enabled (Render).

## 3) Frontend (Netlify)
Publica la carpeta `public/` de este kit. Dentro vienen:
- `index.html` (panel mínimo para probar OTP, presign+upload, crear paquete y abrir ZIP).
- `_redirects` para proxy de `/api/*`, `/auth/*` y `/share/*` al backend.

Edita `_redirects` y cambia la URL de Render por tu **backend**.

## 4) Flujo rápido de prueba
1. Abre Netlify → botón **/api/health** debe responder 200.
2. En "Login con OTP": ingresa **correo** *o* **teléfono** y presiona *Enviar OTP*.  
3. Captura el OTP recibido y presiona *Verificar y guardar token*.
4. Sube 1–2 archivos → *Subir* (presign + PUT + complete).
5. Crea paquete → *Crear paquete* → se abrirá `/share/:id`.
6. Presiona **Descargar todo (ZIP)**: baja desde Render directo.

## 5) Troubleshooting
- **404 en `/presign`** desde Netlify → revisa `_redirects`: la regla debe ser `/api/*  https://<backend>/api/:splat  200`.
- **ZIP no descarga (ERR_INVALID_RESPONSE)** → asegúrate de tener `BACKEND_PUBLIC_ORIGIN` en el backend y que sea la URL de Render con HTTPS.
- **CORS 403 origin_not_allowed** → `ALLOWED_ORIGINS` debe ser JSON array con la URL exacta de Netlify **y** cualquier preview `*.netlify.app` se permite automáticamente.
- **OTP no llega** → si no configuraste Twilio/SendGrid/SMTP, el servidor imprime en logs `"[SMS:demo]"` o `"[MAIL:demo]"` simulado.

## 6) Seguridad / Candado
- `assertEnv()` valida que no se despliegue en prod sin llaves ni CORS.
- `Object.freeze(process.env)` evita mutaciones accidentales.
- Endpoint de diagnóstico: `GET /api/diag` con header `x-config-token: CONFIG_DIAG_TOKEN` (solo lectura).

## 7) Postman Collection
Incluida: `Mixtli-Transfer.postman_collection.json`. Variables:
- `base_url` → tu **Netlify** o **Render** (para probar directo).
- `backend_origin` → URL de Render (para endpoints directos, si quieres).
- `token` → Bearer JWT.
- `config_token` → para `/api/diag`.
- `share_id` → UUID del paquete para `/api/pack/:id` y ZIP.
