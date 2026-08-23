import { motion, AnimatePresence } from 'framer-motion'
import type { SecurityEvent } from '../types'
import { THREAT_COLORS, THREAT_LABELS } from '../types'

interface EventFeedProps {
  events: SecurityEvent[]
  onSelect: (ev: SecurityEvent) => void
}

const ACTION_STYLE: Record<SecurityEvent['action_taken'], string> = {
  ALLOW: 'text-emerald-400/80',
  BLOCK: 'text-rose-400',
  THROTTLE: 'text-amber-400',
  BLACKLIST: 'text-rose-500 font-bold',
}

/**
 * Live security event feed. Blocked/throttled entries slide in with an amber/red
 * flash; clicking any row opens the Intercept Inspector.
 */
export function EventFeed({ events, onSelect }: EventFeedProps) {
  const visible = events.slice(-40).reverse()

  return (
    <div className="flex h-full flex-col overflow-hidden">
      <div className="flex-1 space-y-1 overflow-y-auto pr-1">
        <AnimatePresence initial={false}>
          {visible.map((ev) => {
            const color = THREAT_COLORS[ev.threat_type]
            const dropped = ev.action_taken === 'BLOCK' || ev.action_taken === 'BLACKLIST'
            return (
              <motion.button
                key={ev.timestamp + ev.client_ip + ev.route}
                layout
                initial={{ opacity: 0, x: 24 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.25 }}
                onClick={() => onSelect(ev)}
                className={`block w-full rounded border-l-2 bg-panel-2/60 px-2 py-1.5 text-left text-[11px] hover:bg-panel-2 ${
                  dropped ? 'border-rose-500' : 'border-transparent'
                }`}
              >
                <div className="flex items-center gap-2">
                  <span className="tabular-nums text-slate-500">
                    {ev.timestamp.slice(11, 19)}
                  </span>
                  <span className="text-cyan-300/90">{ev.client_ip}</span>
                  <span className="truncate text-slate-400">{ev.route}</span>
                  <span className="ml-auto shrink-0 rounded px-1 text-[9px] tracking-wider"
                    style={{ color, background: color + '1a' }}>
                    {THREAT_LABELS[ev.threat_type]}
                  </span>
                  <span className={`shrink-0 text-[9px] ${ACTION_STYLE[ev.action_taken]}`}>
                    {ev.action_taken}
                  </span>
                </div>
              </motion.button>
            )
          })}
        </AnimatePresence>
      </div>
    </div>
  )
}
