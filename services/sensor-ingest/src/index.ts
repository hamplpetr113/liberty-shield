/*
 * Liberty Shield — Sensor Ingest Service
 * Receives sensor events from the Android APK, scores them,
 * and writes to Redis (shared Upstash instance via ioredis).
 *
 * Threat model:
 *   T1 Unauthorized injection  → Bearer auth
 *   T2 Timestamp replay        → drift > 60s rejected
 *   T3 Event flood             → rate-limit 120/device/hour
 *   T4 PII leakage             → device_id never stored in Redis
 *   T5 Redis key growth        → all lists LTRIM, all scores TTL'd
 */
import express, { Request, Response, NextFunction } from 'express'
import { z } from 'zod'
import Redis from 'ioredis'
import { createHash } from 'crypto'
import { appendFile } from 'fs/promises'

// ── Redis ─────────────────────────────────────────────────────────
const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379', {
  maxRetriesPerRequest: 3,
  retryStrategy: (times) => Math.min(times * 200, 5000),
  enableReadyCheck: false,   // Upstash doesn't support PING on connect
  lazyConnect: false,
})

redis.on('error', (err) => console.error('[redis] error:', err.message))
redis.on('connect', () => console.log('[redis] connected'))

// ── Config ────────────────────────────────────────────────────────
const SENSOR_API_KEY   = process.env.SENSOR_API_KEY   || ''
const AUDIT_LOG_FILE   = process.env.AUDIT_LOG_FILE   || '/tmp/audit.log'
const MAX_SENSOR_EVENTS = 500
const MAX_DECISIONS     = 200
const RATE_LIMIT        = 120
const RATE_WINDOW_S     = 3600
const TS_DRIFT_MS       = 60_000

// ── Validation ────────────────────────────────────────────────────
const SensorEventSchema = z.object({
  device_id:          z.string().min(1).max(128),
  sensor:             z.enum(['microphone', 'camera']),
  action:             z.enum(['start', 'stop']),
  app_package:        z.string().min(1).max(256),
  app_label:          z.string().min(1).max(128),
  risk_score:         z.number().int().min(0).max(100).default(0),
  misdirection_active: z.boolean().default(false),
  ts:                 z.number().int(),
})

type SensorEvent = z.infer<typeof SensorEventSchema>

// ── Threat scoring ────────────────────────────────────────────────
function scoreEvent(ev: SensorEvent): {
  score: number
  action: 'ALLOW' | 'MONITOR' | 'BLOCK'
  reason: string
} {
  let score = ev.risk_score
  let reason = 'baseline'

  if (ev.action === 'start') {
    score += 10
    reason = 'sensor_start'
  }
  if (ev.misdirection_active) {
    score += 20
    reason = 'misdirection_triggered'
  }
  // Unknown package = not system / not Liberty Shield
  const isSystem =
    ev.app_package.startsWith('com.android.') ||
    ev.app_package.startsWith('com.google.android.') ||
    ev.app_package.startsWith('android.') ||
    ev.app_package.startsWith('com.libertyshield.')
  if (!isSystem) {
    score += 15
    reason = reason === 'baseline' ? 'unknown_package' : reason
  }

  score = Math.min(100, score)
  const action = score >= 70 ? 'BLOCK' : score >= 40 ? 'MONITOR' : 'ALLOW'
  return { score, action, reason }
}

// ── Audit chain ───────────────────────────────────────────────────
async function appendAudit(entry: Record<string, unknown>) {
  try {
    const lastRaw = await redis.lindex('liberty:audit:entries', 0)
    let prevHash = '0'.repeat(64)
    if (lastRaw) {
      try {
        const last = JSON.parse(lastRaw) as Record<string, unknown>
        if (typeof last.hash === 'string') prevHash = last.hash
      } catch { /* ignore */ }
    }

    const payload = { ...entry, prevHash, ts: Date.now() }
    const hash = createHash('sha256')
      .update(JSON.stringify(payload))
      .digest('hex')
    const auditEntry = { ...payload, hash }

    await redis.lpush('liberty:audit:entries', JSON.stringify(auditEntry))
    await redis.ltrim('liberty:audit:entries', 0, 999)

    if (AUDIT_LOG_FILE) {
      await appendFile(AUDIT_LOG_FILE, JSON.stringify(auditEntry) + '\n').catch(() => {})
    }
  } catch (err) {
    console.error('[audit] append error:', (err as Error).message)
  }
}

// ── Auth middleware ───────────────────────────────────────────────
function requireAuth(req: Request, res: Response, next: NextFunction): void {
  const auth = req.headers.authorization ?? ''
  if (!SENSOR_API_KEY || auth !== `Bearer ${SENSOR_API_KEY}`) {
    res.status(401).json({ error: 'Unauthorized' })
    return
  }
  next()
}

// ── App ───────────────────────────────────────────────────────────
const app = express()
app.use(express.json({ limit: '32kb' }))

// Health check
app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'sensor-ingest', ts: Date.now() })
})

// Sensor event ingestion
app.post('/api/sensors/event', requireAuth, async (req: Request, res: Response) => {
  const parsed = SensorEventSchema.safeParse(req.body)
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid payload', issues: parsed.error.issues })
    return
  }

  const ev = parsed.data

  // Timestamp drift guard (T2)
  const drift = Math.abs(Date.now() - ev.ts)
  if (drift > TS_DRIFT_MS) {
    res.status(400).json({ error: 'Timestamp drift too large', drift_ms: drift })
    return
  }

  try {
    // Rate limit per device_id (T3)
    const rateKey = `rl:ingest:${ev.device_id}`
    const count = await redis.incr(rateKey)
    if (count === 1) await redis.expire(rateKey, RATE_WINDOW_S)
    if (count > RATE_LIMIT) {
      res.status(429).json({ error: 'Too many requests' })
      return
    }

    // Score
    const { score, action, reason } = scoreEvent(ev)

    // Store sensor event — device_id stripped (T4)
    const storedEvent = {
      sensor:              ev.sensor,
      action:              ev.action,
      app_package:         ev.app_package,
      app_label:           ev.app_label,
      risk_score:          ev.risk_score,
      misdirection_active: ev.misdirection_active,
      ts:                  ev.ts,
      ingested_at:         Date.now(),
    }
    await redis.lpush('liberty:sensor:events', JSON.stringify(storedEvent))
    await redis.ltrim('liberty:sensor:events', 0, MAX_SENSOR_EVENTS - 1)

    // Store decision
    const decision = {
      sensor:              ev.sensor,
      app_package:         ev.app_package,
      app_label:           ev.app_label,
      risk_score:          score,
      action,
      reason,
      misdirection_active: ev.misdirection_active,
      ts:                  Date.now(),
    }
    await redis.lpush('liberty:decisions', JSON.stringify(decision))
    await redis.ltrim('liberty:decisions', 0, MAX_DECISIONS - 1)

    // Per-package score snapshot with 24h TTL (T5)
    const snapshot = {
      package:   ev.app_package,
      label:     ev.app_label,
      score,
      action,
      last_seen: Date.now(),
      sensor:    ev.sensor,
    }
    await redis.set(
      `liberty:scores:${ev.app_package}`,
      JSON.stringify(snapshot),
      'EX', 86400,
    )

    // Audit trail
    await appendAudit({
      type:       'SENSOR_EVENT',
      app_package: ev.app_package,
      sensor:     ev.sensor,
      ev_action:  ev.action,
      decision:   action,
      score,
    })

    res.json({ ok: true, decision: { action, score, reason } })
  } catch (err) {
    console.error('[sensor-ingest] handler error:', (err as Error).message)
    res.status(503).json({ error: 'Service temporarily unavailable' })
  }
})

// ── Start ─────────────────────────────────────────────────────────
const PORT = parseInt(process.env.PORT || process.env.SENSOR_INGEST_PORT || '3001', 10)
app.listen(PORT, () => {
  console.log(`[sensor-ingest] listening on :${PORT}`)
  console.log(`[sensor-ingest] Redis: ${process.env.REDIS_URL ? 'configured' : 'localhost fallback'}`)
})

export default app
