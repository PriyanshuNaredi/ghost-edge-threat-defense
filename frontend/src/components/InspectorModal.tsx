import { motion, AnimatePresence } from 'framer-motion'
import type { SecurityEvent } from '../types'
import { THREAT_COLORS, THREAT_LABELS } from '../types'

interface InspectorModalProps {
  event: SecurityEvent | null
  onClose: () => void
}

/**
 * Live Intercept Inspector: glassmorphic modal showing the raw request headers,
 * the flagged payload string, and the rule-matching confidence for a single
 * intercepted request.
 */
export function InspectorModal({ event, onClose }: InspectorModalProps) {
  return (
    <AnimatePresence>
      {event && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="fixed inset-0 z-40 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm"
          onClick={onClose}
        >
          <motion.div
            initial={{ opacity: 0, y: 32, scale: 0.96 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 16, scale: 0.97 }}
            transition={{ type: 'spring', damping: 26, stiffness: 300 }}
            onClick={(e) => e.stopPropagation()}
            className="glass glow-cyan w-full max-w-2xl rounded-xl p-6"
          >
            <div className="flex items-start justify-between">
              <div>
                <div className="text-[10px] tracking-[0.3em] text-slate-500">
                  INTERCEPT INSPECTOR
                </div>
                <div className="mt-1 flex items-center gap-3">
                  <span
                    className="rounded px-2 py-0.5 text-xs font-bold tracking-wider"
                    style={{
                      color: THREAT_COLORS[event.threat_type],
                      background: THREAT_COLORS[event.threat_type] + '1a',
                      border: `1px solid ${THREAT_COLORS[event.threat_type]}44`,
                    }}
                  >
                    {THREAT_LABELS[event.threat_type]}
                  </span>
                  <span className="text-sm text-slate-300">{event.client_ip}</span>
                  <span className="text-xs text-slate-500">{event.timestamp}</span>
                </div>
              </div>
              <button
                onClick={onClose}
                className="rounded border border-slate-700 px-2 py-1 text-xs text-slate-400 hover:border-slate-500 hover:text-slate-200"
              >
                ESC ✕
              </button>
            </div>

            {/* verdict row */}
            <div className="mt-4 grid grid-cols-3 gap-3 text-center">
              <div className="rounded-lg bg-panel-2/80 p-3">
                <div className="text-[9px] tracking-widest text-slate-500">ANOMALY SCORE</div>
                <div className="mt-1 text-2xl font-bold tabular-nums text-rose-400">
                  {event.score.toFixed(0)}
                </div>
              </div>
              <div className="rounded-lg bg-panel-2/80 p-3">
                <div className="text-[9px] tracking-widest text-slate-500">CONFIDENCE</div>
                <div className="mt-1 text-2xl font-bold tabular-nums text-cyan-300">
                  {event.confidence ? `${(event.confidence * 100).toFixed(0)}%` : '—'}
                </div>
              </div>
              <div className="rounded-lg bg-panel-2/80 p-3">
                <div className="text-[9px] tracking-widest text-slate-500">ACTION</div>
                <div
                  className={`mt-1 text-2xl font-bold ${
                    event.action_taken === 'ALLOW' ? 'text-emerald-400' : 'text-rose-400'
                  }`}
                >
                  {event.action_taken}
                </div>
              </div>
            </div>

            {/* flagged payload */}
            <div className="mt-4">
              <div className="text-[9px] tracking-widest text-slate-500">FLAGGED PAYLOAD</div>
              <div className="mt-1 overflow-x-auto rounded-lg border border-rose-500/30 bg-rose-500/5 p-3 font-mono text-xs text-rose-300">
                {event.payload || event.route}
              </div>
            </div>

            {/* raw headers */}
            <div className="mt-4">
              <div className="text-[9px] tracking-widest text-slate-500">RAW REQUEST HEADERS</div>
              <div className="mt-1 max-h-44 overflow-y-auto rounded-lg border border-slate-700/60 bg-black/40 p-3 font-mono text-[11px] leading-relaxed">
                <div className="text-cyan-300">
                  GET {event.route} HTTP/1.1
                </div>
                {(event.headers ?? []).map(([k, v], i) => (
                  <div key={i}>
                    <span className="text-slate-500">{k}: </span>
                    <span className="text-slate-300">{v}</span>
                  </div>
                ))}
                {(!event.headers || event.headers.length === 0) && (
                  <div className="text-slate-600">— headers not captured for allowed traffic —</div>
                )}
              </div>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  )
}
