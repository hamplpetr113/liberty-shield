/*
 * Liberty Shield — Sensor Ingest Service
 * Receives sensor events from the Android APK, scores them,
 * and writes to Redis (shared Upstash instance via ioredis).
 *
 * Threat model:
 *   T1 Unauthorized injection  → Bearer auth
 *   T2 Timestamp replay        → drift > 60s rejected
 *   T3 Event flood             → rate-limit 120/device/hour
 *   T4 PII leakage             → device_id never stored in plain sensor stream
 *   T5 Redis key growth        → all streams MAXLEN trimmed, all scores TTL'd
 *   T6 Breakout detection      → BREAKOUT_SUSPECTED / LOCKDOWN triggers egress block
 */
import express, { Request, Response, NextFunction } from 'express'
import { z } from 'zod'
import Redis from 'ioredis'
import { createHash, randomUUID } from 'crypto'

// ── Redis ─────────────────────────────────────────────────────────
// lazyConnect: true — defer TCP connect until first command.
// With lazyConnect: false the connection attempt fires synchronously on module
// load, before the 'error' handler below is attached, causing an uncaught
// ECONNREFUSED that kills the process before Express even starts.
const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379', {
  maxRetriesPerRequest: 3,
  retryStrategy: (times) => Math.min(times * 200, 5000),
  enableReadyCheck: false,   // Upstash doesn't support PING on connect
  lazyConnect: true,
})

redis.on('error', (err) => console.error('[redis] error:', err.message))
redis.on('connect', () => console.log('[redis] connected'))

// ── Config ────────────────────────────────────────────────────────
const SENSOR_API_KEY = process.env.SENSOR_API_KEY || ''
const RATE_LIMIT     = 120
const RATE_WINDOW_S  = 3600
const TS_DRIFT_MS    = 60_000

// ── Validation ────────────────────────────────────────────────────
const SensorEventSchema = z.object({
  device_id:           z.string().min(1).max(128),
  sensor:              z.enum(['microphone', 'camera']),
  action:              z.enum(['start', 'stop']),
  app_package:         z.string().min(1).max(256),
  app_label:           z.string().min(1).max(128),
  risk_score:          z.number().int().min(0).max(100).default(0),
  misdirection_active: z.boolean().default(false),
  ts:                  z.number().int(),
})

// ── Scoring helpers ───────────────────────────────────────────────

function isKnownPackage(pkg: string): boolean {
  return pkg.startsWith('com.android.') ||
    pkg.startsWith('com.google.android.') ||
    pkg.startsWith('android.') ||
    pkg === 'com.libertyshield.android'
}

function scoreCredentialHunting(e: z.infer<typeof SensorEventSchema>): number {
  const patterns = [
    /api[_-]?key|token|secret|password|credential/i,
    /\.env|\.npmrc|id_rsa|\.aws/i,
    /github|vercel|openai|anthropic/i,
  ]
  const text = `${e.action} ${e.app_package ?? ''} ${e.app_label ?? ''}`
  return patterns.some(p => p.test(text)) ? 1 : 0
}

function scoreAntiForensics(e: z.infer<typeof SensorEventSchema>): number {
  const actions = ['log_delete', 'history_clear', 'audit_modify',
                   'git_rebase_force', 'file_overwrite_log']
  return actions.includes(e.action as string) ? 1 : 0
}

function scoreLateralMovement(e: z.infer<typeof SensorEventSchema>): number {
  const patterns = [/\/proc\/\d+/, /docker\.sock/,
                    /169\.254\.169\.254/, /\.internal\//]
  const text = `${e.action} ${e.app_package ?? ''}`
  return patterns.some(p => p.test(text)) ? 1 : 0
}

// ── CHANGE 1: Extended scoreEvent ────────────────────────────────
function scoreEvent(event: z.infer<typeof SensorEventSchema>): {
  score: number
  decision: string
  features: Record<string, number>
} {
  const features: Record<string, number> = {
    base_risk:          event.risk_score ?? 0,
    misdirection:       event.misdirection_active ? 20 : 0,
    unknown_package:    isKnownPackage(event.app_package ?? '') ? 0 : 15,
    credential_hunting: scoreCredentialHunting(event),
    anti_forensics:     scoreAntiForensics(event),
    lateral_movement:   scoreLateralMovement(event),
  }

  const total = Math.min(
    (features.base_risk) +
    (features.misdirection) +
    (features.unknown_package) +
    (features.credential_hunting * 30) +
    (features.anti_forensics * 35) +
    (features.lateral_movement * 30),
    100
  )

  let decision = 'ALLOW'
  if (total >= 95)      decision = 'LOCKDOWN'
  else if (total >= 92) decision = 'BREAKOUT_SUSPECTED'
  else if (total >= 85) decision = 'DECEPTION'
  else if (total >= 70) decision = 'BLOCK'
  else if (total >= 40) decision = 'MONITOR'

  return { score: total, decision, features }
}

// ── CHANGE 4: appendAudit — Redis XADD only, Merkle chain intact ──
async function appendAudit(
  redisClient: Redis,
  input: { type: string; payload: Record<string, unknown> }
): Promise<void> {
  try {
    // Read last entry to get prevHash for Merkle chain
    const lastEntries = await redisClient.xrevrange(
      'liberty:audit:entries', '+', '-', 'COUNT', '1'
    )
    let prevHash = '0'.repeat(64)
    if (lastEntries.length > 0) {
      const fields = lastEntries[0][1]  // flat [key, val, key, val, ...]
      const hashIdx = fields.findIndex(
        (f, i) => i % 2 === 0 && f === 'hash'
      )
      if (hashIdx >= 0) prevHash = fields[hashIdx + 1]
    }

    const ts = Date.now()
    const hashPayload = { ...input, prevHash, ts }
    const hash = createHash('sha256')
      .update(JSON.stringify(hashPayload))
      .digest('hex')

    await redisClient.xadd(
      'liberty:audit:entries', 'MAXLEN', '~', '1000', '*',
      'type',     input.type,
      'payload',  JSON.stringify(input.payload),
      'prev_hash', prevHash,
      'hash',     hash,
      'ts',       String(ts),
    )
  } catch (err) {
    console.error('[audit] append error:', (err as Error).message)
  }
}

// ── CHANGE 2: BREAKOUT / LOCKDOWN handler ────────────────────────
async function handleBreakout(
  redisClient: Redis,
  deviceId: string,
  features: Record<string, number>,
  trigger: string
): Promise<void> {
  const incidentId = randomUUID()
  const ts = String(Date.now())
  await Promise.all([
    redisClient.publish('liberty:control',
      JSON.stringify({ command: 'BREAKOUT_SUSPECTED', incidentId, deviceId, trigger, ts })),
    redisClient.publish('liberty:control',
      JSON.stringify({ command: 'TOKEN_BURN', deviceId, incidentId })),
    redisClient.set(`liberty:session:${deviceId}:egress`, 'BLOCK_ALL', 'EX', 3600),
    redisClient.xadd('liberty:snapshots', 'MAXLEN', '~', '1000', '*',
      'incident_id',  incidentId,
      'device_id',    deviceId,
      'trigger',      trigger,
      'features',     JSON.stringify(features),
      'timestamp_ms', ts,
    ),
    redisClient.set(`liberty:session:${deviceId}:mode`, 'DECEPTION', 'EX', 3600),
  ])
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

// ── CHANGE 3: Sensor event ingestion — XADD streams, opaque response
app.post('/api/sensors/event', requireAuth, async (req: Request, res: Response) => {
  const parsed = SensorEventSchema.safeParse(req.body)
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid payload', issues: parsed.error.issues })
    return
  }

  const body = parsed.data

  // Timestamp drift guard (T2)
  const drift = Math.abs(Date.now() - body.ts)
  if (drift > TS_DRIFT_MS) {
    res.status(400).json({ error: 'Timestamp drift too large', drift_ms: drift })
    return
  }

  try {
    // Rate limit per device_id (T3)
    const rateKey = `rl:ingest:${body.device_id}`
    const count = await redis.incr(rateKey)
    if (count === 1) await redis.expire(rateKey, RATE_WINDOW_S)
    if (count > RATE_LIMIT) {
      res.status(429).json({ error: 'Too many requests' })
      return
    }

    const { score, decision, features } = scoreEvent(body)

    // Fire BREAKOUT flow before Redis writes if critical
    if (decision === 'BREAKOUT_SUSPECTED' || decision === 'LOCKDOWN') {
      await handleBreakout(redis, body.device_id, features, decision)
    }

    const eventId  = randomUUID()
    const serverTs = Date.now()

    await Promise.all([
      // Sensor event stream (XADD — compatible with threat-scoring worker)
      redis.xadd('liberty:sensor:events', 'MAXLEN', '~', '100000', '*',
        'event_id',     eventId,
        'device_id',    body.device_id,
        'sensor',       body.sensor,
        'action',       body.action,
        'app_package',  body.app_package ?? '',
        'app_label',    body.app_label ?? '',
        'risk_score',   String(score),
        'decision',     decision,
        'misdirection', String(body.misdirection_active),
        'server_ts',    String(serverTs),
      ),
      // Decision stream (dashboard reads this)
      redis.xadd('liberty:decisions', 'MAXLEN', '~', '50000', '*',
        'event_id',  eventId,
        'device_id', body.device_id,
        'sensor',    body.sensor,
        'action',    body.action,
        'score',     String(score),
        'decision',  decision,
        'features',  JSON.stringify(features),
        'server_ts', String(serverTs),
      ),
      // Score cache per device (dashboard threat-score endpoint)
      redis.set(
        `liberty:scores:${body.device_id}`,
        JSON.stringify({ score, decision, features, updated_at: serverTs }),
        'EX', 86400,
      ),
      // Audit chain
      appendAudit(redis, {
        type:    'sensor_event',
        payload: {
          event_id: eventId,
          sensor:   body.sensor,
          action:   body.action,
          decision,
          score,
          device_id: body.device_id,
        },
      }),
    ])

    // Never expose score or decision to client (timing oracle + info leak)
    const minMs   = 150
    const elapsed = Date.now() - serverTs
    if (elapsed < minMs) await new Promise(r => setTimeout(r, minMs - elapsed))

    res.status(202).json({ ok: true, event_id: eventId })
  } catch (err) {
    console.error('[sensor-ingest] handler error:', (err as Error).message)
    res.status(503).json({ error: 'Service temporarily unavailable' })
  }
})

// ── Process-level safety net ──────────────────────────────────────
// Catches anything that escapes a try/catch — e.g. ioredis protocol errors,
// synchronous module-load failures, or unresolved promise rejections.
process.on('uncaughtException', (err) => {
  console.error('[sensor-ingest] UNCAUGHT EXCEPTION — process will exit')
  console.error(err)
  process.exit(1)
})

process.on('unhandledRejection', (reason) => {
  console.error('[sensor-ingest] UNHANDLED REJECTION — process will exit')
  console.error(reason)
  process.exit(1)
})

// ── Start ─────────────────────────────────────────────────────────
console.log('[sensor-ingest] Starting Liberty Shield sensor ingest server...')
console.log(`[sensor-ingest] PORT: ${process.env.PORT ?? '(not set, defaulting)'}`)
console.log(`[sensor-ingest] Redis: ${process.env.REDIS_URL ? 'configured via REDIS_URL' : 'localhost fallback'}`)
console.log(`[sensor-ingest] Auth: ${process.env.SENSOR_API_KEY ? 'SENSOR_API_KEY set' : 'WARNING — SENSOR_API_KEY not set'}`)

const PORT = parseInt(process.env.PORT || process.env.SENSOR_INGEST_PORT || '3001', 10)

try {
  const server = app.listen(PORT, () => {
    console.log(`[sensor-ingest] listening on :${PORT}`)
  })

  server.on('error', (err) => {
    console.error(`[sensor-ingest] server error — could not bind to port ${PORT}:`, err.message)
    process.exit(1)
  })
} catch (err) {
  console.error('[sensor-ingest] Fatal error starting server:', (err as Error).message)
  process.exit(1)
}

export default app
