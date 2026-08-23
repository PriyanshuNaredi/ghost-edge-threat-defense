import { useMemo } from 'react'
import { motion } from 'framer-motion'
import type { SecurityEvent } from '../types'
import { THREAT_COLORS, THREAT_LABELS } from '../types'

interface TrafficGridProps {
  events: SecurityEvent[]
}

/**
 * Global/Node traffic grid: buckets the last N events by route and renders a
 * live heat grid of request distribution. Cell intensity tracks volume;
 * border color tracks the worst threat seen on that route.
 */
export function TrafficGrid({ events }: TrafficGridProps) {
  const nodes = useMemo(() => {
    const recent = events.slice(-200)
    const byRoute = new Map<string, { count: number; worst: number; threat: SecurityEvent['threat_type'] }>()
    for (const ev of recent) {
      const cur = byRoute.get(ev.route) ?? { count: 0, worst: 0, threat: 'NONE' as const }
      cur.count++
      if (ev.score > cur.worst) {
        cur.worst = ev.score
        cur.threat = ev.threat_type
      }
      byRoute.set(ev.route, cur)
    }
    return [...byRoute.entries()]
      .sort((a, b) => b[1].count - a[1].count)
      .slice(0, 12)
  }, [events])

  const maxCount = Math.max(1, ...nodes.map(([, v]) => v.count))

  return (
    <div className="grid grid-cols-3 gap-2">
      {nodes.map(([route, v]) => {
        const intensity = v.count / maxCount
        const color = THREAT_COLORS[v.threat]
        return (
          <motion.div
            key={route}
            layout
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            className="rounded-md border p-2"
            style={{
              borderColor: color + '44',
              background: `linear-gradient(135deg, ${color}${Math.round(intensity * 28 + 6).toString(16).padStart(2, '0')}, transparent)`,
            }}
            title={`${route}: ${v.count} req`}
          >
            <div className="truncate text-[10px] text-slate-400">{route}</div>
            <div className="mt-1 flex items-center justify-between">
              <span className="text-sm font-bold tabular-nums" style={{ color }}>
                {v.count}
              </span>
              <span className="text-[9px] tracking-wider" style={{ color }}>
                {THREAT_LABELS[v.threat]}
              </span>
            </div>
            <div className="mt-1 h-0.5 overflow-hidden rounded bg-slate-800">
              <motion.div
                className="h-full"
                style={{ background: color }}
                animate={{ width: `${intensity * 100}%` }}
                transition={{ duration: 0.4 }}
              />
            </div>
          </motion.div>
        )
      })}
      {nodes.length === 0 && (
        <div className="col-span-3 py-6 text-center text-xs text-slate-600">
          AWAITING TELEMETRY…
        </div>
      )}
    </div>
  )
}
