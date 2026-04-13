/*
 * GET /api/security/stream
 * Server-Sent Events — pushes SystemOverview + last 5 decisions every 2s.
 * Keep-alive ping every 15s.
 *
 * Auth: x-ls-api-key header OR ?key= query param
 * (EventSource browser API cannot set custom headers, so query param is required)
 */
import { Redis } from '@upstash/redis'
import { NextRequest } from 'next/server'

const kv = new Redis({
  url: process.env.KV_REST_API_URL!,
  token: process.env.KV_REST_API_TOKEN!,
})

async function buildPayload() {
  const [lockdownRaw, decisions, allDecisions] = await Promise.all([
    kv.get<string>('liberty:control:lockdown'),
    kv.lrange<string>('liberty:decisions', 0, 4),
    kv.lrange<string>('liberty:decisions', 0, 19),
  ])

  const lockdown_active = lockdownRaw === '1'

  const parsedEvents = decisions
    .map((d) => {
      try { return typeof d === 'string' ? JSON.parse(d) : d }
      catch { return null }
    })
    .filter(Boolean)

  const topThreatScore = allDecisions.reduce((max, d) => {
    try {
      const parsed = typeof d === 'string' ? JSON.parse(d) : d as Record<string, number>
      return Math.max(max, parsed.risk_score ?? 0)
    } catch { return max }
  }, 0)

  const status: 'ACTIVE' | 'MIRROR' | 'LOCKDOWN' =
    lockdown_active ? 'LOCKDOWN'
    : topThreatScore >= 70 ? 'MIRROR'
    : 'ACTIVE'

  return {
    status,
    layers_active: 7,
    top_threat_score: topThreatScore,
    lockdown_active,
    events: parsedEvents,
    timestamp_ms: Date.now(),
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
      'Content-Type':  'text/event-stream; charset=utf-8',
      'Cache-Control': 'no-cache, no-store',
      'Connection':    'keep-alive',
      'X-Accel-Buffering': 'no',
    },
  })
}
