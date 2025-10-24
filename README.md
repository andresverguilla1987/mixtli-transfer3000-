# MixtliTransfer3000 backend v2.5.0

## Novedades
- Links con password opcional (`/f/:slug`) + branding + QR + stats
- Email al descargar (opcional)
- OTP real en DB (SendGrid/SMTP)
- Planes PRO/PROMAX con expiración
- Rate limit IP para /auth y /presign
- Admin (/admin/metrics) + Cron (/tasks/cleanup)
- Paquetes con límite de descargas

## Run
1) `cp .env.example .env` y rellena
2) `npm i`
3) `npm start`

## Notas
- Si `CAPTCHA_REQUIRED=true`, manda header `x-captcha: ok` en /auth/register
- Si envías `linkPassword` en `/api/presign`, recibirás `publicUrl` `/f/:slug`.
- Para descarga directa sin password también te llega `downloadUrl` directo.
