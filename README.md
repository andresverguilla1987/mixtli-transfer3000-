# Mixtli Plan Buttons (Render ZIP)

Pequeño backend listo para **Render** que habilita los **botones de paquetes (planes)** sin tocar tu módulo **OTP**.

## Endpoints
- `GET /api/health` → salud
- `GET /api/plan` → plan actual y límites (por token/usuario)
- `POST /api/plan/upgrade` → body `{ "plan": "PRO" | "PROMAX" }`
- `POST /api/plan/downgrade` → body `{ "plan": "FREE" }`

> Nota: Guarda el plan **en memoria** por `Authorization: Bearer <token>` o `X-User-Id` (si no envías, usa un slot por defecto). Ideal para demo/integración rápida. Si requieres persistencia real, cambia a Postgres más adelante.

## Deploy en Render
1. Crea un **nuevo servicio Web** en Render (Node).
2. Sube este ZIP directamente (Deploy from a **Blueprint** o **directorio**).
3. **Build Command**: _no requiere build_
4. **Start Command**: `node server.js`
5. **Runtime**: Node 18+
6. Variables de entorno:
   - `PORT` = `10000` (opcional)
   - `ALLOWED_ORIGINS` = `["https://lighthearted-froyo-9dd448.netlify.app", "http://localhost:5173"]`
     - Ajusta el dominio de tu Netlify si cambió.

## Cómo integrarlo con tu UI
- Para **mostrar el plan actual** y los **límites**: `GET https://<tu-app-onrender>.onrender.com/api/plan`
- Para **subir a PRO**: `POST /api/plan/upgrade` con body `{ "plan": "PRO" }`
- Para **subir a PROMAX**: `POST /api/plan/upgrade` con body `{ "plan": "PROMAX" }`
- Para **bajar a FREE**: `POST /api/plan/downgrade` con body `{ "plan": "FREE" }`

### Ejemplo de fetch (frontend)
```js
async function upgrade(plan){
  const res = await fetch("/api/plan/upgrade", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ plan })
  });
  const data = await res.json();
  console.log(data);
}
```

## Importante
- CORS estricto por `ALLOWED_ORIGINS` (array JSON).
- **No toca OTP** ni autenticación existente.
- Puedes colocar delante un **reverse proxy** o integrar estos endpoints bajo `/api` del backend principal más adelante.