Mixtli Transfer 3000 — Frontend v2.4.1
========================================

Archivos
--------
- index.html
- styles.css
- app.js

Cómo usar
---------
1) Despliega estos archivos en Netlify (sitio estático).
2) En la interfaz, pega tu **Backend URL** (Render) y guarda.
3) Elige archivos, ajusta la expiración y pulsa **Subir todo**.

Detalles técnicos
-----------------
- Solicita presign a `POST /api/presign` con `{ files: [{name,size,type}], expiresSeconds }`.
- Sube con **XMLHttpRequest** y `body: file` para progreso real (sin `duplex`).
- Muestra enlaces `getUrl` (24h) y `objectUrl` (no público salvo que abras el bucket).
