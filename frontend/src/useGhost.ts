import { useEffect, useRef, useState } from 'react'
import type { SecurityEvent, GatewayStats } from './types'

const MAX_EVENTS = 400
const MAX_SERIES = 120

export interface ThroughputPoint {
  t: number
  total: number
  blocked: number
}

export interface GhostState {
  connected: boolean
  events: SecurityEvent[]
  stats: GatewayStats | null
  series: ThroughputPoint[]
  threatLevel: number
  lastBlock: SecurityEvent | null
  blockPulse: number
}

/**
 * useGhost connects to the gateway's WebSocket telemetry stream and its
 * /ghost/stats control endpoint, maintaining rolling buffers for the HUD.
 */
export function useGhost(wsUrl: string, statsUrl: string): GhostState {
  const [connected, setConnected] = useState(false)
  const [events, setEvents] = useState<SecurityEvent[]>([])
  const [stats, setStats] = useState<GatewayStats | null>(null)
  const [series, setSeries] = useState<ThroughputPoint[]>([])
  const [threatLevel, setThreatLevel] = useState(0)
  const [lastBlock, setLastBlock] = useState<SecurityEvent | null>(null)
  const [blockPulse, setBlockPulse] = useState(0)

  const windowRef = useRef<{ total: number; blocked: number }>({ total: 0, blocked: 0 })
  const wsRef = useRef<WebSocket | null>(null)
  const retryRef = useRef<number>(0)

  // WebSocket telemetry loop with exponential-backoff reconnect.
  useEffect(() => {
    let disposed = false

    const connect = () => {
      if (disposed) return
      const ws = new WebSocket(wsUrl)
      wsRef.current = ws

      ws.onopen = () => {
        setConnected(true)
        retryRef.current = 0
      }

      ws.onmessage = (msg) => {
        try {
          const ev: SecurityEvent = JSON.parse(msg.data)
          windowRef.current.total++
          const isBlock = ev.action_taken === 'BLOCK' || ev.action_taken === 'BLACKLIST'
          if (isBlock) windowRef.current.blocked++

          setEvents((prev) => {
            const next = [...prev, ev]
            return next.length > MAX_EVENTS ? next.slice(next.length - MAX_EVENTS) : next
          })

          if (isBlock) {
            setLastBlock(ev)
            setBlockPulse((p) => p + 1)
          }
        } catch {
          // ignore malformed frames
        }
      }

      ws.onclose = () => {
        setConnected(false)
        if (!disposed) {
          const delay = Math.min(1000 * 2 ** retryRef.current, 15000)
          retryRef.current++
          setTimeout(connect, delay)
        }
      }
      ws.onerror = () => ws.close()
    }

    connect()
    return () => {
      disposed = true
      wsRef.current?.close()
    }
  }, [wsUrl])

  // Throughput sampler: fold the per-message window into a 500ms series.
  useEffect(() => {
    const id = setInterval(() => {
      const w = windowRef.current
      setSeries((prev) => {
        const next = [...prev, { t: Date.now(), total: w.total, blocked: w.blocked }]
        windowRef.current = { total: 0, blocked: 0 }
        return next.length > MAX_SERIES ? next.slice(next.length - MAX_SERIES) : next
      })
    }, 500)
    return () => clearInterval(id)
  }, [])

  // Control-plane stats polling.
  useEffect(() => {
    let stop = false
    const poll = async () => {
      try {
        const res = await fetch(statsUrl)
        if (res.ok && !stop) setStats(await res.json())
      } catch {
        // gateway unreachable; keep last known stats
      }
    }
    poll()
    const id = setInterval(poll, 2000)
    return () => {
      stop = true
      clearInterval(id)
    }
  }, [statsUrl])

  // Threat level: exponential moving average of recent block intensity + max score.
  useEffect(() => {
    const recent = events.slice(-60)
    const blocks = recent.filter(
      (e) => e.action_taken === 'BLOCK' || e.action_taken === 'BLACKLIST',
    )
    const maxScore = recent.reduce((m, e) => Math.max(m, e.score), 0)
    const intensity = Math.min(1, blocks.length / 18)
    const level = Math.min(100, Math.round(intensity * 60 + (maxScore / 100) * 40))
    setThreatLevel((prev) => Math.round(prev * 0.6 + level * 0.4))
  }, [events])

  return { connected, events, stats, series, threatLevel, lastBlock, blockPulse }
}

export function useClock(): string {
  const [now, setNow] = useState(() => new Date())
  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), 1000)
    return () => clearInterval(id)
  }, [])
  return now.toISOString().slice(11, 19) + ' UTC'
}

export function formatUptime(secs: number): string {
  const h = Math.floor(secs / 3600)
  const m = Math.floor((secs % 3600) / 60)
  const s = secs % 60
  return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`
}
