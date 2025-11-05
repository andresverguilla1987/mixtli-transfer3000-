
// Mixtli Plan Buttons — lightweight backend for Render
// Purpose: make package (plan) buttons work without touching OTP modules.
// Author: ChatGPT (Mixtli helper)
// Runtime: Node 18+
// Endpoints: GET /api/health, GET /api/plan, POST /api/plan/upgrade, POST /api/plan/downgrade
// Notes: In-memory store by user token; replace with DB later if needed.

import express from "express";
import cors from "cors";
import morgan from "morgan";
import { planCatalog, limitTextByPlan, defaultPlan } from "./src/planLimits.js";

const app = express();

// ----- Config -----
const PORT = process.env.PORT || 10000;

// Allowed origins as JSON array in env var ALLOWED_ORIGINS
let ALLOWED_ORIGINS = [];
try {
  ALLOWED_ORIGINS = JSON.parse(process.env.ALLOWED_ORIGINS || "[]");
} catch (e) {
  console.warn("Invalid ALLOWED_ORIGINS, falling back to permissive CORS in dev.");
}

const corsOptions = {
  origin: function (origin, callback) {
    // allow server-to-server or local tools with no origin
    if (!origin) return callback(null, true);
    if (ALLOWED_ORIGINS.length === 0) return callback(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
    return callback(new Error("CORS: Origin not allowed: " + origin));
  },
  credentials: true,
};

app.use(morgan("dev"));
app.use(express.json({ limit: "1mb" }));
app.use(cors(corsOptions));

// ----- Minimal in-memory "user plan" store -----
// Key by an optional Authorization bearer token or X-User-Id header;
// Fall back to a single shared default slot.
const plansByUser = new Map();

function getUserKey(req) {
  const auth = req.headers["authorization"];
  if (auth && auth.startsWith("Bearer ")) return auth.slice(7);
  const xuid = req.headers["x-user-id"];
  if (xuid) return String(xuid);
  return "__default__";
}

function getCurrentPlan(req) {
  const key = getUserKey(req);
  if (!plansByUser.has(key)) plansByUser.set(key, defaultPlan);
  return plansByUser.get(key);
}

function setCurrentPlan(req, plan) {
  const key = getUserKey(req);
  plansByUser.set(key, plan);
}

app.get("/api/health", (req, res) => {
  res.json({ ok: true, name: "Mixtli Plan Buttons", version: "1.0.0" });
});

app.get("/api/plan", (req, res) => {
  const current = getCurrentPlan(req);
  const info = planCatalog[current];
  return res.json({
    plan: current,
    info,
    limits_text: limitTextByPlan(current),
  });
});

app.post("/api/plan/upgrade", (req, res) => {
  const { plan } = req.body || {};
  if (!plan || !planCatalog[plan]) {
    return res.status(400).json({ error: "Invalid or missing `plan`" });
  }
  // Only allow upgrades to higher tiers than current
  const current = getCurrentPlan(req);
  const order = ["FREE", "PRO", "PROMAX"];
  if (order.indexOf(plan) <= order.indexOf(current)) {
    return res.status(400).json({ error: `Already on ${current} or higher` });
  }
  setCurrentPlan(req, plan);
  return res.json({
    ok: true,
    message: `Upgraded to ${plan}`,
    plan,
    limits_text: limitTextByPlan(plan),
  });
});

app.post("/api/plan/downgrade", (req, res) => {
  const { plan } = req.body || {};
  if (!plan || plan !== "FREE") {
    return res.status(400).json({ error: "Only downgrade to FREE is supported here" });
  }
  setCurrentPlan(req, "FREE");
  return res.json({
    ok: true,
    message: "Downgraded to FREE",
    plan: "FREE",
    limits_text: limitTextByPlan("FREE"),
  });
});

// Fallback 404
app.use((req, res) => {
  res.status(404).json({ error: "Not found" });
});

// Error handler
// (Ensure CORS headers are present even on errors for better DX)
app.use((err, req, res, next) => {
  console.error("Error:", err?.message || err);
  res.status(400).json({ error: String(err?.message || err) });
});

app.listen(PORT, () => {
  console.log(`Mixtli Plan Buttons ready on :${PORT}`);
});
