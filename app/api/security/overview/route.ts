/*
 * GET /api/security/overview
 * Returns a SystemOverview snapshot from Redis Streams.
 * Auth: x-ls-api-key header === DASHBOARD_API_KEY env var
 *
 * Reads liberty:decisions via XREVRANGE (Stream key, not List).
 */
import { Redis } from '@upstash/redis'
import { NextRequest, NextResponse } from 'next/server'
import { xrevrange } from '@/lib/redis'

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
    const [decisions, lockdownRaw] = await Promise.all([
      xrevrange(kv, 'liberty:decisions', 100),
      kv.get<string>('liberty:control:lockdown'),
    ])

    const lockdown_active = lockdownRaw === '1'

    // Events in last hour — use server_ts written by ingest service
    const oneHourAgo = Date.now() - 3_600_000
    const eventsLastHour = decisions.filter(m =>
      Number(m.server_ts ?? 0) > oneHourAgo
    ).length

    // Top threat score across last 100 decisions
    const topThreatScore = decisions.reduce(
      (max, m) => Math.max(max, Number(m.score ?? 0)), 0
    )

    const status: 'ACTIVE' | 'MIRROR' | 'LOCKDOWN' =
      lockdown_active   ? 'LOCKDOWN'
      : topThreatScore >= 85 ? 'MIRROR'
      : 'ACTIVE'

    return NextResponse.json({
      status,
      layers_active:    7,
      top_threat_score: topThreatScore,
      events_last_hour: eventsLastHour,
      lockdown_active,
      timestamp_ms:     Date.now(),
    })
  } catch (err) {
    console.error('[overview] error:', (err as Error).message)
    return NextResponse.json({ error: 'Service error' }, { status: 503 })
  }
}
