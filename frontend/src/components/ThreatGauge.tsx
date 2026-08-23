import { useEffect, useRef } from 'react'
import { motion } from 'framer-motion'

interface ThreatGaugeProps {
  level: number // 0-100
  blockPulse: number // increments on every dropped request
}

interface Particle {
  angle: number
  radius: number
  speed: number
  life: number
  size: number
}

/**
 * Glowing radial threat gauge. The arc sweeps from cyan (calm) through amber to
 * red (critical). Every dropped request fires a particle pulse ring outward
 * from the gauge rim, rendered on an overlay canvas.
 */
export function ThreatGauge({ level, blockPulse }: ThreatGaugeProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const particlesRef = useRef<Particle[]>([])
  const rafRef = useRef<number>(0)

  const clamped = Math.max(0, Math.min(100, level))
  const color = clamped < 35 ? '#22d3ee' : clamped < 70 ? '#fbbf24' : '#f43f5e'
  const status = clamped < 35 ? 'NOMINAL' : clamped < 70 ? 'ELEVATED' : 'CRITICAL'

  // Spawn a particle burst whenever a malicious request is dropped.
  useEffect(() => {
    if (blockPulse === 0) return
    const burst: Particle[] = []
    for (let i = 0; i < 26; i++) {
      burst.push({
        angle: Math.random() * Math.PI * 2,
        radius: 78 + Math.random() * 8,
        speed: 0.8 + Math.random() * 2.2,
        life: 1,
        size: 1 + Math.random() * 2.2,
      })
    }
    particlesRef.current.push(...burst)
  }, [blockPulse])

  // Particle animation loop.
  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return

    const dpr = window.devicePixelRatio || 1
    const size = 240
    canvas.width = size * dpr
    canvas.height = size * dpr
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0)

    const tick = () => {
      ctx.clearRect(0, 0, size, size)
      const cx = size / 2
      const cy = size / 2
      const alive: Particle[] = []

      for (const p of particlesRef.current) {
        p.radius += p.speed
        p.life -= 0.022
        if (p.life <= 0) continue
        alive.push(p)
        const x = cx + Math.cos(p.angle) * p.radius
        const y = cy + Math.sin(p.angle) * p.radius
        ctx.beginPath()
        ctx.arc(x, y, p.size * p.life, 0, Math.PI * 2)
        ctx.fillStyle = `rgba(244, 63, 94, ${p.life * 0.9})`
        ctx.fill()
      }
      particlesRef.current = alive
      rafRef.current = requestAnimationFrame(tick)
    }
    rafRef.current = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(rafRef.current)
  }, [])

  // Arc geometry: 270° sweep starting at 135°.
  const R = 88
  const CIRC = 2 * Math.PI * R
  const sweep = 0.75
  const dash = (clamped / 100) * sweep * CIRC

  return (
    <div className="relative flex items-center justify-center" style={{ width: 240, height: 240 }}>
      <canvas ref={canvasRef} style={{ width: 240, height: 240 }} className="absolute inset-0" />

      <svg width={240} height={240} viewBox="0 0 240 240" className="absolute inset-0">
        <defs>
          <filter id="gaugeGlow" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="6" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        {/* track */}
        <circle
          cx={120} cy={120} r={R} fill="none" stroke="#16233a" strokeWidth={10}
          strokeDasharray={`${sweep * CIRC} ${CIRC}`}
          strokeLinecap="round"
          transform="rotate(135 120 120)"
        />
        {/* value arc */}
        <motion.circle
          cx={120} cy={120} r={R} fill="none"
          stroke={color} strokeWidth={10}
          strokeLinecap="round"
          strokeDasharray={`${dash} ${CIRC}`}
          transform="rotate(135 120 120)"
          filter="url(#gaugeGlow)"
          animate={{ strokeDasharray: `${dash} ${CIRC}`, stroke: color }}
          transition={{ duration: 0.6, ease: 'easeOut' }}
        />
        {/* tick marks */}
        {Array.from({ length: 28 }).map((_, i) => {
          const a = (135 + (i / 27) * 270) * (Math.PI / 180)
          const x1 = 120 + Math.cos(a) * 100
          const y1 = 120 + Math.sin(a) * 100
          const x2 = 120 + Math.cos(a) * 106
          const y2 = 120 + Math.sin(a) * 106
          return <line key={i} x1={x1} y1={y1} x2={x2} y2={y2} stroke="#1e3a5f" strokeWidth={1.5} />
        })}
      </svg>

      <div className="relative z-10 flex flex-col items-center">
        <motion.span
          key={clamped}
          initial={{ scale: 1.15, opacity: 0.6 }}
          animate={{ scale: 1, opacity: 1 }}
          className="text-5xl font-bold tabular-nums"
          style={{ color, textShadow: `0 0 24px ${color}66` }}
        >
          {clamped}
        </motion.span>
        <span className="mt-1 text-[10px] tracking-[0.3em] text-slate-500">THREAT INDEX</span>
        <motion.span
          key={status}
          initial={{ opacity: 0, y: 4 }}
          animate={{ opacity: 1, y: 0 }}
          className="mt-2 rounded border px-2 py-0.5 text-[10px] tracking-widest"
          style={{ color, borderColor: color + '55', background: color + '11' }}
        >
          {status}
        </motion.span>
      </div>
    </div>
  )
}
