/*
 * GET /api/security/events
 * Returns the last 50 scored decisions from liberty:decisions list.
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
    const raw = await kv.lrange<string>('liberty:decisions', 0, 49)

    const events = raw
      .map((item) => {
        try {
          return typeof item === 'string' ? JSON.parse(item) : item
        } catch {
          return null
        }
      })
      .filter(Boolean)

    return NextResponse.json({ events })
  } catch (err) {
    console.error('[events] error:', (err as Error).message)
    return NextResponse.json({ error: 'Service error' }, { status: 503 })
  }
}
