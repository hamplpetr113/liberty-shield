'use client'

import { useEffect, useRef, useState, useCallback } from 'react'

// ── Types ────────────────────────────────────────────────────────────────────

export interface SecurityOverview {
  status: string
  layers_active: number
  top_threat_score: number
  events_last_hour: number
  lockdown_active: boolean
  timestamp_ms: number
}

export interface SecurityEvent {
  id?: string
  package_name: string
  sensor: string
  action: string
  risk_score: number
  misdirection_active: boolean
  ingested_at: number
  score?: number
  decision?: string
  reason?: string
}

export interface StreamData {
  overview: SecurityOverview | null
  events: SecurityEvent[]
  topThreats: Array<{ key: string; score: number }>
}

export interface UseSecurityStreamResult {
  data: StreamData | null
  connected: boolean
  error: string | null
  reconnectCount: number
}

// ── Constants ─────────────────────────────────────────────────────────────────

const INITIAL_BACKOFF_MS = 2_000
const MAX_BACKOFF_MS = 30_000
const MAX_RECONNECTS = 10

// ── Hook ──────────────────────────────────────────────────────────────────────

export function useSecurityStream(): UseSecurityStreamResult {
  const [data, setData] = useState<StreamData | null>(null)
  const [connected, setConnected] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [reconnectCount, setReconnectCount] = useState(0)

  const esRef = useRef<EventSource | null>(null)
  const backoffRef = useRef(INITIAL_BACKOFF_MS)
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const mountedRef = useRef(true)

  const apiKey = process.env.NEXT_PUBLIC_DASHBOARD_API_KEY ?? ''

  const cleanup = useCallback(() => {
    if (reconnectTimerRef.current) {
      clearTimeout(reconnectTimerRef.current)
      reconnectTimerRef.current = null
    }
    if (esRef.current) {
      esRef.current.close()
      esRef.current = null
    }
  }, [])

  const connect = useCallback(() => {
    if (!mountedRef.current) return
    cleanup()

    const url = `/api/security/stream${apiKey ? `?key=${encodeURIComponent(apiKey)}` : ''}`
    const es = new EventSource(url)
    esRef.current = es

    es.onopen = () => {
      if (!mountedRef.current) return
      setConnected(true)
      setError(null)
      backoffRef.current = INITIAL_BACKOFF_MS
      setReconnectCount(0)
    }

    es.onmessage = (ev: MessageEvent) => {
      if (!mountedRef.current) return
      try {
        const parsed = JSON.parse(ev.data) as StreamData
        setData(parsed)
      } catch {
        // ignore parse errors — keep existing data
      }
    }

    es.addEventListener('ping', () => {
      // server heartbeat — connection still alive, no action needed
    })

    es.onerror = () => {
      if (!mountedRef.current) return
      setConnected(false)
      es.close()
      esRef.current = null

      setReconnectCount(prev => {
        const next = prev + 1
        if (next >= MAX_RECONNECTS) {
          setError(`Stream disconnected after ${MAX_RECONNECTS} reconnect attempts`)
          return next
        }
        const delay = Math.min(backoffRef.current, MAX_BACKOFF_MS)
        backoffRef.current = Math.min(backoffRef.current * 2, MAX_BACKOFF_MS)
        reconnectTimerRef.current = setTimeout(() => {
          if (mountedRef.current) connect()
        }, delay)
        return next
      })
    }
  }, [apiKey, cleanup])

  useEffect(() => {
    mountedRef.current = true
    connect()
    return () => {
      mountedRef.current = false
      cleanup()
    }
  }, [connect, cleanup])

  return { data, connected, error, reconnectCount }
}
