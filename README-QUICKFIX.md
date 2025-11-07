# Mixtli Backend FIX (OTP real, sin demo)

Rutas aceptadas (para evitar 404):
- **/auth/register** y **/api/auth/register**
- **/auth/verify-otp**, **/api/auth/verify-otp** y **/auth/verify**

## Pruebas rápidas (reemplaza $BASE)

# Email (SendGrid o SMTP configurado)
curl -sS -X POST "$BASE/auth/register" -H "Content-Type: application/json" -d '{"email":"tu@correo.com"}'

# SMS (Twilio configurado)
curl -sS -X POST "$BASE/auth/register" -H "Content-Type: application/json" -d '{"phone":"+5215555555555"}'

# Luego verifica (cambia el OTP)
curl -sS -X POST "$BASE/auth/verify-otp" -H "Content-Type: application/json" -d '{"email":"tu@correo.com","otp":"123456"}'
