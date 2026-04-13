/*
 * GET /api/security/stream
 * Server-Sent Events — pushes StreamData every 2s.
 * Keep-alive ping every 15s.
 *
 * Auth: x-ls-api-key header OR ?key= query param
 * (EventSource browser API cannot set custom headers, so query param is required)
 *
 * Payload shape matches StreamData in useSecurityStream:
 *   { overview: SecurityOverview, events: SecurityEvent[], topThreats: {key,score}[] }
 *
 * Reads liberty:decisions via XREVRANGE (Stream key, not List).
 */
import { Redis } from '@upstash/redis'
import { NextRequest } from 'next/server'
import { xrevrange } from '@/lib/redis'

const kv = new Redis({
  url: process.env.KV_REST_API_URL!,
  token: process.env.KV_REST_API_TOKEN!,
})

async function buildPayload() {
  const [decisions, lockdown] = await Promise.all([
    xrevrange(kv, 'liberty:decisions', 20),
    kv.get<string>('liberty:control:lockdown'),
  ])

  const isLocked = lockdown === '1'

  const topScore = decisions.reduce(
    (max, m) => Math.max(max, Number(m.score ?? 0)), 0
  )

  const status = isLocked ? 'LOCKDOWN' : topScore >= 85 ? 'MIRROR' : 'ACTIVE'

  // Map last 5 decisions to SecurityEvent shape
  const events = decisions.slice(0, 5).map(m => ({
    event_id:            m.event_id         ?? '',
    package_name:        m.device_id        ?? '',
    sensor:              m.sensor           ?? 'unknown',
    action:              m.action           ?? 'unknown',
    risk_score:          Number(m.score     ?? 0),
    decision:            m.decision         ?? 'ALLOW',
    misdirection_active: m.misdirection     === 'true',
    ingested_at:         Number(m.server_ts ?? Date.now()),
  }))

  // Top threats from per-device score cache (liberty:scores:*)
  const scoreKeys = await kv.keys('liberty:scores:*')
  const topThreatsRaw = await Promise.all(
    scoreKeys.slice(0, 10).map(async (k) => {
      const raw = await kv.get<string>(k)
      if (!raw) return null
      try {
        const parsed = (typeof raw === 'string' ? JSON.parse(raw) : raw) as {
          score?: number
          decision?: string
        }
        return {
          key:   k,                        // full key — dashboard strips prefix
          score: Number(parsed.score ?? 0),
        }
      } catch {
        return null
      }
    })
  )
  const topThreats = (topThreatsRaw.filter(Boolean) as { key: string; score: number }[])
    .sort((a, b) => b.score - a.score)

  return {
    overview: {
      status,
      layers_active:    7,
      top_threat_score: topScore,
      lockdown_active:  isLocked,
      events_last_hour: decisions.length,
      timestamp_ms:     Date.now(),
    },
    events,
    topThreats,
  }
}

export async function GET(request: NextRequest) {
  // Auth: header or query param (EventSource workaround)
  const headerKey = request.headers.get('x-ls-api-key')
  const queryKey  = new URL(request.url).searchParams.get('key')
  const dashKey   = process.env.DASHBOARD_API_KEY

  if (dashKey && headerKey !== dashKey && queryKey !== dashKey) {
    return new Response('Unauthorized', { status: 401 })
  }

  const encoder = new TextEncoder()
  let pingCount = 0

  const stream = new ReadableStream({
    async start(controller) {
      const enqueue = (text: string) => {
        try { controller.enqueue(encoder.encode(text)) } catch { /* client gone */ }
      }

      const sendData = async () => {
        try {
          const payload = await buildPayload()
          enqueue(`data: ${JSON.stringify(payload)}\n\n`)
        } catch { /* skip frame on Redis error */ }
      }

      // Send immediately on connect
      await sendData()

      const dataTimer = setInterval(async () => {
        if (request.signal.aborted) {
          clearInterval(dataTimer)
          clearInterval(pingTimer)
          try { controller.close() } catch { /* already closed */ }
          return
        }
        await sendData()
      }, 2000)

      const pingTimer = setInterval(() => {
        if (request.signal.aborted) return
        enqueue(`: ping ${++pingCount}\n\n`)
      }, 15_000)

      request.signal.addEventListener('abort', () => {
        clearInterval(dataTimer)
        clearInterval(pingTimer)
        try { controller.close() } catch { /* already closed */ }
      })
    },
  })

  return new Response(stream, {
    headers: {
      'Content-Type':      'text/event-stream; charset=utf-8',
      'Cache-Control':     'no-cache, no-store',
      'Connection':        'keep-alive',
      'X-Accel-Buffering': 'no',
    },
  })
}
