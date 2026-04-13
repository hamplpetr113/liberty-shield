/*
 * GET /api/security/threat-score
 * Returns top 10 ThreatScoreSnapshot entries from liberty:scores:* keys.
 * Auth: x-ls-api-key header
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
    const keys = await kv.keys('liberty:scores:*')
    if (keys.length === 0) {
      return NextResponse.json({ scores: [] })
    }

    const limited = keys.slice(0, 20)
    const values = await Promise.all(limited.map((k) => kv.get<string>(k)))

    const scores = values
      .map((v) => {
        try {
          return typeof v === 'string' ? JSON.parse(v) : v
        } catch {
          return null
        }
      })
      .filter(Boolean)
      .sort((a: Record<string, number>, b: Record<string, number>) =>
        (b.score ?? 0) - (a.score ?? 0)
      )
      .slice(0, 10)

    return NextResponse.json({ scores })
  } catch (err) {
    console.error('[threat-score] error:', (err as Error).message)
    return NextResponse.json({ error: 'Service error' }, { status: 503 })
  }
}
