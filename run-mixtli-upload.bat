@echo off
setlocal
REM One-click runner for Mixtli bulk upload
set PS1="%~dp0mixtli-bulk-upload.ps1"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File %PS1% -Folder "%USERPROFILE%\Uploads"
echo.
echo Listo. Presiona una tecla para cerrar...
pause >nul
