import { useEffect, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { useGhost, useClock, formatUptime } from './useGhost'
import type { SecurityEvent } from './types'
import { THREAT_COLORS, THREAT_LABELS } from './types'
import { Sparkline } from './components/Sparkline'
import { ThreatGauge } from './components/ThreatGauge'
import { TrafficGrid } from './components/TrafficGrid'
import { EventFeed } from './components/EventFeed'
import { InspectorModal } from './components/InspectorModal'

const WS_URL = `ws://${location.host}/ws`
const STATS_URL = '/ghost/stats'

export default function App() {
  const { connected, events, stats, series, threatLevel, lastBlock, blockPulse } =
    useGhost(WS_URL, STATS_URL)
  const clock = useClock()
  const [selected, setSelected] = useState<SecurityEvent | null>(null)
  const [alerts, setAlerts] = useState<SecurityEvent[]>([])

  // Slide-in security alerts for every dropped request.
  useEffect(() => {
    if (!lastBlock) return
    setAlerts((prev) => [...prev.slice(-3), lastBlock])
    const id = setTimeout(() => {
      setAlerts((prev) => prev.filter((a) => a !== lastBlock))
    }, 4200)
    return () => clearTimeout(id)
  }, [lastBlock, blockPulse])

  // ESC closes the inspector.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && setSelected(null)
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  return (
    <div className="scanlines min-h-screen bg-abyss p-4 text-slate-300">
      {/* ── Header ─────────────────────────────────────────────── */}
      <header className="glass glow-cyan mb-4 flex items-center justify-between rounded-xl px-5 py-3">
        <div className="flex items-center gap-4">
          <div className="relative h-3 w-3">
            <span className="absolute inset-0 animate-ping rounded-full bg-cyan-400/60" />
            <span
              className={`absolute inset-0 rounded-full ${connected ? 'bg-cyan-400' : 'bg-rose-500'}`}
            />
          </div>
          <div>
            <h1 className="text-lg font-bold tracking-[0.35em] text-cyan-300">
              GHOST<span className="text-slate-600"> //</span>{' '}
              <span className="text-slate-400">EDGE THREAT DEFENSE</span>
            </h1>
            <div className="text-[10px] tracking-widest text-slate-500">
              WAF INTERCEPTOR · TOKEN-BUCKET RATE LIMITER · ANOMALY SCORER
            </div>
          </div>
        </div>

        <div className="flex items-center gap-6 text-right">
          <Stat label="UPTIME" value={stats ? formatUptime(stats.uptime_seconds) : '--:--:--'} />
          <Stat label="TOTAL" value={stats ? String(stats.total_requests) : '0'} color="#22d3ee" />
          <Stat label="BLOCKED" value={stats ? String(stats.blocked) : '0'} color="#f43f5e" />
          <Stat label="BLACKLIST" value={stats ? String(stats.blacklisted) : '0'} color="#fbbf24" />
          <div>
            <div className="text-[9px] tracking-widest text-slate-500">LINK</div>
            <div className={`text-sm font-bold ${connected ? 'text-emerald-400' : 'text-rose-400'}`}>
              {connected ? 'STREAMING' : 'OFFLINE'}
            </div>
          </div>
          <div className="text-sm tabular-nums text-slate-400">{clock}</div>
        </div>
      </header>

      {/* ── Main grid ──────────────────────────────────────────── */}
      <div className="grid grid-cols-12 gap-4">
        {/* Left: traffic grid + sparklines */}
        <section className="col-span-12 space-y-4 lg:col-span-3">
          <Panel title="NODE TRAFFIC GRID">
            <TrafficGrid events={events} />
          </Panel>
          <Panel title="THROUGHPUT">
            <Sparkline series={series} color="#22d3ee" label="requests" />
            <div className="mt-3">
              <Sparkline series={series} color="#f43f5e" label="intercepts" height={44} />
            </div>
          </Panel>
        </section>

        {/* Center: threat matrix visualizer */}
        <section className="col-span-12 lg:col-span-5">
          <Panel title="THREAT MATRIX VISUALIZER" className="h-full">
            <div className="flex h-full flex-col items-center justify-center py-4">
              <ThreatGauge level={threatLevel} blockPulse={blockPulse} />
              <div className="mt-2 grid w-full grid-cols-3 gap-2 text-center text-[10px]">
                <Legend color="#22d3ee" label="CLEAN" />
                <Legend color="#fbbf24" label="SUSPICIOUS" />
                <Legend color="#f43f5e" label="DROPPED" />
              </div>
            </div>
          </Panel>
        </section>

        {/* Right: live event feed */}
        <section className="col-span-12 lg:col-span-4">
          <Panel title="LIVE INTERCEPT FEED" className="h-[560px]">
            <div className="h-full">
              <EventFeed events={events} onSelect={setSelected} />
            </div>
          </Panel>
        </section>
      </div>

      {/* ── Slide-in security alerts ───────────────────────────── */}
      <div className="pointer-events-none fixed right-4 top-20 z-30 flex w-80 flex-col gap-2">
        <AnimatePresence>
          {alerts.map((ev) => (
            <motion.div
              key={ev.timestamp + ev.client_ip}
              initial={{ opacity: 0, x: 120 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 120 }}
              transition={{ type: 'spring', damping: 24, stiffness: 280 }}
              className="glass glow-red rounded-lg border-l-4 border-rose-500 p-3"
            >
              <div className="flex items-center justify-between text-[10px] tracking-widest">
                <span className="font-bold text-rose-400">⛔ THREAT DROPPED</span>
                <span style={{ color: THREAT_COLORS[ev.threat_type] }}>
                  {THREAT_LABELS[ev.threat_type]}
                </span>
              </div>
              <div className="mt-1 truncate text-xs text-slate-300">
                {ev.client_ip} → {ev.route}
              </div>
              <div className="mt-0.5 text-[10px] text-slate-500">
                score {ev.score.toFixed(0)} · {ev.action_taken}
              </div>
            </motion.div>
          ))}
        </AnimatePresence>
      </div>

      <InspectorModal event={selected} onClose={() => setSelected(null)} />
    </div>
  )
}

function Stat({ label, value, color = '#94a3b8' }: { label: string; value: string; color?: string }) {
  return (
    <div>
      <div className="text-[9px] tracking-widest text-slate-500">{label}</div>
      <div className="text-sm font-bold tabular-nums" style={{ color }}>
        {value}
      </div>
    </div>
  )
}

function Panel({
  title,
  children,
  className = '',
}: {
  title: string
  children: React.ReactNode
  className?: string
}) {
  return (
    <div className={`glass rounded-xl p-4 ${className}`}>
      <div className="mb-3 flex items-center gap-2">
        <span className="h-1 w-1 rounded-full bg-cyan-400" />
        <h2 className="text-[10px] tracking-[0.3em] text-slate-500">{title}</h2>
      </div>
      {children}
    </div>
  )
}

function Legend({ color, label }: { color: string; label: string }) {
  return (
    <div className="flex items-center justify-center gap-1.5">
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: color }} />
      <span className="tracking-widest text-slate-500">{label}</span>
    </div>
  )
}
