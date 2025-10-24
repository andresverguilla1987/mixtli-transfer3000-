# MixtliTransfer3000 Backend v2.2.0
- OTP login (email/phone) ➜ `POST /api/auth/register` y `POST /api/auth/verify-otp`
- **Upgrade de plan** ➜ `POST /api/plan/upgrade` con `{plan:"PRO"}` o `{plan:"PROMAX"}`
- **Auto-downgrade** si `plan_expires_at < now()` (se aplica al autenticar)
- `GET /api/me` para ver `{
  id, email, plan, plan_expires_at
}`

### Variables nuevas (opcionales)
- `PRO_PERIOD_DAYS=30`
- `PROMAX_PERIOD_DAYS=30`

### Ejemplo de flujo PRO
1) Login OTP → token JWT
2) `POST /api/plan/upgrade` con Bearer token y body `{"plan":"PRO"}`
3) Subir con `/api/presign` (ya usa tu `user.plan`)