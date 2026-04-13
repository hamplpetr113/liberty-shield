/*
 * GET /api/security/events
 * Returns the last 50 scored decisions from liberty:decisions Stream.
 * Auth: x-ls-api-key header
 *
 * Reads via XREVRANGE (Stream key, not List — LRANGE would fail).
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
    const messages = await xrevrange(kv, 'liberty:decisions', 50)

    const events = messages.map(m => ({
      event_id:            m.event_id          ?? '',
      package_name:        m.device_id         ?? '',
      sensor:              m.sensor            ?? 'unknown',
      action:              m.action            ?? 'unknown',
      risk_score:          Number(m.score      ?? 0),
      decision:            m.decision          ?? 'ALLOW',
      misdirection_active: m.misdirection      === 'true',
      ingested_at:         Number(m.server_ts  ?? Date.now()),
    }))

    return NextResponse.json({ events })
  } catch (err) {
    console.error('[events] error:', (err as Error).message)
    return NextResponse.json({ error: 'Service error' }, { status: 503 })
  }
}
