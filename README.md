# Mixtli Transfer MAX — Backend FIX (v2.15.2)

Arreglos:
- OTP con diagnóstico: `otp_db_error` vs `otp_channel_failed`
- `ALLOW_DEMO_OTP=true` permite flujo de prueba (imprime OTP en logs)
- CORS incluye `x-config-token`
- Regex y sanitizados corregidos

## Deploy en Render
1. Node 22.x, Build: `npm install --no-audit --no-fund`, Start: `node --enable-source-maps server.js`.
2. Variables `.env` según `.env.example` (ALLOWED_ORIGINS JSON array).
3. (Opcional) `ALLOW_DEMO_OTP=true` para pruebas sin Twilio/SendGrid/SMTP.

## Smoke
- `GET /api/health`
- `POST /api/auth/register` → `{"ok":true,"msg":"otp_sent"}` o `otp_sent_demo`
- Logs deben mostrar `[DEMO_OTP]` si demo.
