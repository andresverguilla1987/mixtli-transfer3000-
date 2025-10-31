# Mixtli Backend v2.13.1 (fix share URL)

Corrige 404 en `/share/:id` usando APP_BASE_URL para construir el link.

## ENV
- PUBLIC_BASE_URL -> **solo archivos**
- APP_BASE_URL -> **base pública del backend** (Render URL)

