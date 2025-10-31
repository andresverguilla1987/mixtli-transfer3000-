# Mixtli Transfer — Netlify Patch (Routing Only)

This patch **does not change your UI**. It only fixes routing so that
`/share/:id` resolves on Netlify and API calls keep working.

## What this adds
- `_redirects` file to:
  - Proxy `/api/*` (and `/auth/*` if needed) to your Render backend.
  - Serve `/share/:id` from your SPA (`index.html`) to avoid Netlify 404.
  - Optionally fallback all other client routes to SPA.

## How to apply
1. In your Netlify site, make sure the **publish directory** is `public/`.
2. Drop the included `_redirects` file into your repo/site root **or** into `public/`.
   (Either location works; Netlify will pick it up. Prefer the site root.)
3. Set these environment variables in Netlify → Site settings → Build & deploy → Environment:
   - `APP_BASE_URL = https://mixtli-transfer3000.onrender.com`
   - (Optional) `PUBLIC_BASE_URL` — *leave empty*, the backend builds public file URLs.
4. Redeploy the site (Trigger deploy).

## Smoke check
- Visit `/` (home) → generate a package → you should obtain a link like:
  `https://<your-netlify-site>.netlify.app/share/<package-id>`
- Open it in a private window; it should render the SPA, fetch package JSON from:
  `/api/pack/:id` (proxied to Render) and show individual file links.

## Notes
- If you keep a `netlify.toml`, do not duplicate routing rules there; `_redirects` wins.
- Backend must expose: `/api/pack/create`, `/api/pack/:id`, `/share/:id` (optional server html),
  and presign endpoints. Your current backend already supports these routes.
