# Mixtli Transfer — Backend v2.14.7-lock+wt
Parche listo para Render.

```bash
npm install --no-audit --no-fund
npm start
```

Fixes:
- Regex de `normalizePhone` corregido (`[()\s-]`).
- Migración en caliente: añade `password_hash`, `password_salt`, `download_count`, `max_downloads`, `max_total_mb` si faltan.
