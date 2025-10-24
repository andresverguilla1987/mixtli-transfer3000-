# MixtliTransfer3000 Backend v2.1.2 (no-FK)
Build: 2025-10-24T16:29:41.723682Z

- Auto-migraciones **sin FKs** para evitar el choque UUID/BIGINT.
- Mantiene packages, TTL, contadores y share page con QR.
- Seguro para bases donde `users.id` ya es `uuid` y otros esquemas legados.

Si deseas reactivar FKs luego, te paso un script que las agrega condicionalmente, pero primero deja que despliegue limpio.
