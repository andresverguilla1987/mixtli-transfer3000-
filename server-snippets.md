
# Express middlewares: auth, plan, quota

// auth.ts
export function authOptional(req, _res, next) {
  // parse bearer token, set req.user or null
  next();
}
export function authRequired(req, res, next) {
  if (!req.user) return res.status(401).json({error:'auth_required'});
  next();
}

// planLimits.ts
const MB = 1024*1024;
export function limitsFor(plan, durationDaysRequested) {
  if (plan === 'FREE') {
    const sizeCap = Number(process.env.FREE_MAX_UPLOAD_MB)*MB; // 3.5GB
    const ttl = Math.min(
      Number(process.env.FREE_LINK_TTL_MAX_DAYS||30),
      Math.max(Number(process.env.FREE_LINK_TTL_DEFAULT_DAYS||3), durationDaysRequested||3)
    );
    return { sizeCap, ttlDays: ttl };
  }
  if (plan === 'PRO') {
    return {
      sizeCap: Number(process.env.PRO_MAX_UPLOAD_MB|| (40*1024))*MB, // optional generous cap
      ttlDays: Number(process.env.PRO_LINK_TTL_DAYS||7),
      periodDays: Number(process.env.PRO_PERIOD_DAYS||30),
      capBytesPerPeriod: Number(process.env.PRO_MAX_PERIOD_GB||400) * 1024*1024*1024
    };
  }
  if (plan === 'PROMAX') {
    return {
      sizeCap: Number(process.env.PROMAX_MAX_UPLOAD_MB|| (200*1024))*MB,
      ttlDays: Number(process.env.PROMAX_LINK_TTL_DAYS||22),
      periodDays: Number(process.env.PROMAX_PERIOD_DAYS||30),
      capBytesPerPeriod: Infinity
    };
  }
  throw new Error('unknown plan');
}

// quota.ts
import pg from 'pg';
const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });

export async function checkQuotaAndInsertLink({ user, plan, filename, sizeBytes, ttlDays, key, contentType }) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    if (user && (plan === 'PRO' || plan === 'PROMAX')) {
      const { rows } = await client.query(
        `SELECT coalesce(sum(size_bytes),0) AS sum, count(*) AS cnt
         FROM links WHERE user_id=$1 AND created_at >= now() - INTERVAL '30 days'`, [user.id]
      );
      const sum = Number(rows[0].sum||0);
      const cnt = Number(rows[0].cnt||0);
      if (plan === 'PRO') {
        const capBytes = Number(process.env.PRO_MAX_PERIOD_GB||400)*1024*1024*1024;
        if (sum + sizeBytes > capBytes) throw new Error('quota_bytes_exceeded');
        // unlimited links; only bytes cap applies
      }
      // PROMAX: no bytes cap by spec; keep for safety if needed
    } else if (plan === 'FREE') {
      // Track FREE per-account (email/phone). If anonymous not allowed, require register.
      const { rows } = await client.query(
        `SELECT count(*) AS cnt FROM links WHERE (user_id=$1) AND created_at >= now() - INTERVAL '30 days'`, [user?.id]
      );
      const cnt = Number(rows[0].cnt||0);
      // Free rule: 10 links OR 30 days plan window (enforced at UI + server)
      if (cnt >= 10) throw new Error('free_link_count_exceeded');
    }
    const expiresAt = `now() + interval '${ttlDays} days'`;
    await client.query(
      `INSERT INTO links (user_id, plan, key, filename, content_type, size_bytes, expires_at, active)
       VALUES ($1,$2,$3,$4,$5,$6, now() + ($7 || ' days')::interval, true)`,
      [user?.id||null, plan, key, filename, contentType, sizeBytes, ttlDays]
    );
    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}

// In /api/presign route:
// 1) resolve user + plan
// 2) const { sizeCap, ttlDays } = limitsFor(plan, req.body.durationDays);
// 3) if (contentLength > sizeCap) 413
// 4) const key = `mt/${plan}/${new Date().toISOString().slice(0,10)}/${uuid}.${ext}`;
// 5) generate PUT and GET signed URLs
// 6) await checkQuotaAndInsertLink(...);
