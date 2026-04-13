/*
 * GET /api/security/overview
 * Returns a SystemOverview snapshot from Redis.
 * Auth: x-ls-api-key header === DASHBOARD_API_KEY env var
 */
import { Redis } from '@upstash/redis'
import { NextRequest, NextResponse } from 'next/server'

const kv = new Redis({
  url: process.env.KV_REST_API_URL!,
  token: process.env.KV_REST_API_TOKEN!,
})

function authOk(req: NextRequest): boolean {
  const key = req.headers.get('x-ls-api-key')
  const expected = process.env.DASHBOARD_API_KEY
  return !!(expected && key === expected)
}

export async function GET(req: NextRequest) {
  if (!authOk(req)) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }

  try {
    const [lockdownRaw, recentEvents, allDecisions] = await Promise.all([
      kv.get<string>('liberty:control:lockdown'),
      kv.lrange<string>('liberty:sensor:events', 0, 99),
      kv.lrange<string>('liberty:decisions', 0, 19),
    ])

    const lockdown_active = lockdownRaw === '1'

    // Events in last hour
    const oneHourAgo = Date.now() - 3_600_000
    const eventsLastHour = recentEvents.filter((e) => {
      try {
        const parsed = typeof e === 'string' ? JSON.parse(e) : e as Record<string, number>
        return (parsed.ingested_at || parsed.ts || 0) > oneHourAgo
      } catch {
        return false
      }
    }).length

    // Top threat score across last 20 decisions
    const topThreatScore = allDecisions.reduce((max, d) => {
      try {
        const parsed = typeof d === 'string' ? JSON.parse(d) : d as Record<string, number>
        return Math.max(max, parsed.risk_score ?? 0)
      } catch {
        return max
      }
    }, 0)

    const status: 'ACTIVE' | 'MIRROR' | 'LOCKDOWN' =
      lockdown_active ? 'LOCKDOWN'
      : topThreatScore >= 70 ? 'MIRROR'
      : 'ACTIVE'

    return NextResponse.json({
      status,
      layers_active: 7,
      top_threat_score: topThreatScore,
      events_last_hour: eventsLastHour,
      lockdown_active,
      timestamp_ms: Date.now(),
    })
  } catch (err) {
    console.error('[overview] error:', (err as Error).message)
    return NextResponse.json({ error: 'Service error' }, { status: 503 })
  }
}
