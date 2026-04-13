/*
 * GET /api/security/audit
 * Reads the last 20 audit chain entries from Redis and verifies chain integrity.
 * Auth: x-ls-api-key header
 */
import { Redis } from '@upstash/redis'
import { NextRequest, NextResponse } from 'next/server'
import { createHash } from 'crypto'

const kv = new Redis({
  url: process.env.KV_REST_API_URL!,
  token: process.env.KV_REST_API_TOKEN!,
})

function authOk(req: NextRequest): boolean {
  const key = req.headers.get('x-ls-api-key')
  const expected = process.env.DASHBOARD_API_KEY
  return !!(expected && key === expected)
}

interface AuditEntry {
  hash: string
  prevHash: string
  ts: number
  [key: string]: unknown
}

function verifyChain(entries: AuditEntry[]): {
  valid: boolean
  broken_at?: number
  checked: number
} {
  // LRANGE returns newest-first; reverse for oldest-first chain walk
  const ordered = [...entries].reverse()

  for (let i = 0; i < ordered.length; i++) {
    const entry = ordered[i]
    const { hash, ...withoutHash } = entry

    // Re-derive hash and compare
    const expected = createHash('sha256')
      .update(JSON.stringify(withoutHash))
      .digest('hex')

    if (hash !== expected) {
      return { valid: false, broken_at: i, checked: ordered.length }
    }

    // Verify prevHash linkage (skip for first entry)
    if (i > 0 && entry.prevHash !== ordered[i - 1].hash) {
      return { valid: false, broken_at: i, checked: ordered.length }
    }
  }

  return { valid: true, checked: ordered.length }
}

export async function GET(req: NextRequest) {
  if (!authOk(req)) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }

  try {
    const raw = await kv.lrange<string>('liberty:audit:entries', 0, 19)

    const entries = raw
      .map((item) => {
        try {
          return typeof item === 'string' ? JSON.parse(item) : item
        } catch {
          return null
        }
      })
      .filter(Boolean) as AuditEntry[]

    const integrity = verifyChain(entries)

    return NextResponse.json({ entries, integrity })
  } catch (err) {
    console.error('[audit] error:', (err as Error).message)
    return NextResponse.json({ error: 'Service error' }, { status: 503 })
  }
}
