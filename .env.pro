# ——— COMMON (no editar estos a menos que cambie tu infra) ———
S3_ENDPOINT=https://8351c372dedf0e354a3196aff085f0ae.r2.cloudflarestorage.com
S3_REGION=auto
S3_BUCKET=mixtlitransfer
S3_FORCE_PATH_STYLE=true
PORT=10000
ALLOWED_ORIGINS=["https://lighthearted-froyo-9dd448.netlify.app","http://localhost:8888"]

# Pega aquí tus credenciales reales de R2 (obligatorias en Render)
S3_ACCESS_KEY_ID=************************
S3_SECRET_ACCESS_KEY=************************

# ——— PRO ———
# Para uso serio
LINK_TTL_HOURS=72        # 3 días
MAX_UPLOAD_MB=2048       # 2 GB por archivo
