Mixtli Transfer 3000 — Bulk Uploader

Contenido:
- mixtli-bulk-upload.ps1  → Script PowerShell para subir en lote
- run-mixtli-upload.bat   → Lanzador de 1 clic (usa ExecutionPolicy Bypass)
- README.txt              

Uso rápido (recomendado):
1) Descomprime la carpeta donde quieras.
2) Haz doble clic en: run-mixtli-upload.bat
   - Subirá archivos desde %USERPROFILE%\Uploads (crea la carpeta si no existe).
3) Al final imprime la ruta de un CSV con los links GET.

Avanzado (desde PowerShell):
  & "ruta\mixtli-bulk-upload.ps1" -Folder "$env:USERPROFILE\Pictures" -Patterns "*.jpg","*.png","*.pdf" -ExpireSec 604800
