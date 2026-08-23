import { useEffect, useRef } from 'react'
import type { ThroughputPoint } from '../useGhost'

interface SparklineProps {
  series: ThroughputPoint[]
  color: string
  label: string
  height?: number
}

/**
 * Real-time throughput sparkline rendered on <canvas>. Redraws on every new
 * sample; the blocked series is overlaid in red when present.
 */
export function Sparkline({ series, color, label, height = 64 }: SparklineProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return

    const dpr = window.devicePixelRatio || 1
    const w = canvas.clientWidth
    const h = canvas.clientHeight
    if (canvas.width !== w * dpr || canvas.height !== h * dpr) {
      canvas.width = w * dpr
      canvas.height = h * dpr
    }
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
    ctx.clearRect(0, 0, w, h)

    if (series.length < 2) return

    const max = Math.max(4, ...series.map((p) => p.total))
    const stepX = w / (series.length - 1)

    const drawLine = (get: (p: ThroughputPoint) => number, stroke: string, fill?: string) => {
      ctx.beginPath()
      series.forEach((p, i) => {
        const x = i * stepX
        const y = h - (get(p) / max) * (h - 6) - 2
        if (i === 0) ctx.moveTo(x, y)
        else ctx.lineTo(x, y)
      })
      ctx.strokeStyle = stroke
      ctx.lineWidth = 1.5
      ctx.stroke()

      if (fill) {
        ctx.lineTo((series.length - 1) * stepX, h)
        ctx.lineTo(0, h)
        ctx.closePath()
        const grad = ctx.createLinearGradient(0, 0, 0, h)
        grad.addColorStop(0, fill)
        grad.addColorStop(1, 'transparent')
        ctx.fillStyle = grad
        ctx.fill()
      }
    }

    drawLine((p) => p.total, color, color + '26')
    drawLine((p) => p.blocked, '#f43f5e')

    // latest-value dot
    const last = series[series.length - 1]
    const y = h - (last.total / max) * (h - 6) - 2
    ctx.beginPath()
    ctx.arc((series.length - 1) * stepX, y, 2.5, 0, Math.PI * 2)
    ctx.fillStyle = color
    ctx.fill()
  }, [series, color])

  const latest = series.length ? series[series.length - 1] : null

  return (
    <div className="flex flex-col gap-1">
      <div className="flex items-baseline justify-between text-[10px] tracking-widest">
        <span className="text-slate-500 uppercase">{label}</span>
        <span style={{ color }} className="tabular-nums">
          {latest ? `${latest.total * 2}/s` : '—'}
        </span>
      </div>
      <canvas ref={canvasRef} style={{ height }} className="w-full" />
    </div>
  )
}
