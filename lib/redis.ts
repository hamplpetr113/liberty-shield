/**
 * Shared Redis stream helpers for dashboard API routes.
 * Wraps @upstash/redis xrevrange to return a flat array of message objects.
 *
 * Upstash SDK xrevrange signature (v1.34.x):
 *   kv.xrevrange<TData>(key, end, start, count?) → Promise<Record<string, TData>>
 *   where keys = stream entry IDs, values = field-value Records
 *
 * We use Object.values() to get messages in newest-first order.
 * Non-integer string keys (e.g. "1700000000000-0") preserve insertion order in V8.
 */
import { Redis } from '@upstash/redis'

export async function xrevrange(
  kv: Redis,
  key: string,
  count: number
): Promise<Record<string, string>[]> {
  const raw = await kv.xrevrange<Record<string, string>>(key, '+', '-', count)
  if (!raw) return []
  return Object.values(raw)
}
