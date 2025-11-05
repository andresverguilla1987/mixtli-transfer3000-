
// src/planLimits.js
export const defaultPlan = "FREE";

export const planCatalog = {
  FREE: {
    label: "Free",
    maxFileMB: 200,
    maxDownloads: 50,
    ttlDaysDefault: 3,
    ttlDaysOptions: [3, 7, 22, 30],
  },
  PRO: {
    label: "Pro",
    maxFileMB: 4000,
    maxDownloads: 500,
    ttlDaysDefault: 7,
    ttlDaysOptions: [3, 7, 22, 30],
  },
  PROMAX: {
    label: "Pro Max",
    maxFileMB: 10000,
    maxDownloads: 2000,
    ttlDaysDefault: 22,
    ttlDaysOptions: [3, 7, 22, 30],
  },
};

export function limitTextByPlan(plan) {
  const p = planCatalog[plan] || planCatalog.FREE;
  // Keep Spanish text as requested by user context
  return `Límites (${p.label}): Archivo máx ${p.maxFileMB} MB · Descargas máx ${p.maxDownloads} · TTL por defecto ${p.ttlDaysDefault} días`;
}
