/*
 * POST /api/security/lockdown
 * Body: { activate: boolean }
 * Sets liberty:control:lockdown in Redis and enqueues a control command.
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

export async function POST(req: NextRequest) {
  if (!authOk(req)) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }

  let body: { activate?: boolean }
  try {
    body = await req.json()
  } catch {
    return NextResponse.json({ error: 'Invalid JSON' }, { status: 400 })
  }

  if (typeof body.activate !== 'boolean') {
    return NextResponse.json({ error: 'activate must be boolean' }, { status: 400 })
  }

  const activate = body.activate

  try {
    await kv.set('liberty:control:lockdown', activate ? '1' : '0')

    // Enqueue control command (audit trail substitute for PUBLISH)
    const command = {
      command: activate ? 'LOCKDOWN_ACTIVATE' : 'LOCKDOWN_RELEASE',
      ts: Date.now(),
    }
    await kv.lpush('liberty:control:commands', JSON.stringify(command))
    await kv.ltrim('liberty:control:commands', 0, 99)

    return NextResponse.json({ success: true, lockdown_active: activate })
  } catch (err) {
    console.error('[lockdown] error:', (err as Error).message)
    return NextResponse.json({ error: 'Service error' }, { status: 503 })
  }
}
