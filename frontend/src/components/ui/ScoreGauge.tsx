import { useEffect, useRef } from 'react'
import { getScoreColor } from '../../lib/utils'
import { useTheme } from '../../context/ThemeContext'

interface ScoreGaugeProps {
  score: number
  label?: string
  size?: number
}

export default function ScoreGauge({ score, label = 'Risk Score', size = 148 }: ScoreGaugeProps) {
  const circleRef = useRef<SVGCircleElement>(null)
  const { theme } = useTheme()
  const R = 56
  const CIRCUMFERENCE = 2 * Math.PI * R
  const clampedScore = Math.min(100, Math.max(0, score))
  const color = getScoreColor(clampedScore)
  const offset = CIRCUMFERENCE - (clampedScore / 100) * CIRCUMFERENCE

  useEffect(() => {
    if (!circleRef.current) return
    // Trigger animated draw on mount
    circleRef.current.style.transition = 'none'
    circleRef.current.style.strokeDashoffset = String(CIRCUMFERENCE)
    // Force reflow
    void circleRef.current.getBoundingClientRect()
    circleRef.current.style.transition = 'stroke-dashoffset 0.9s cubic-bezier(0.4,0,0.2,1), stroke 0.4s ease'
    circleRef.current.style.strokeDashoffset = String(offset)
  }, [score])

  const cx = size / 2
  const cy = size / 2

  return (
    <div className="flex flex-col items-center gap-1">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        {/* Track */}
        <circle
          cx={cx}
          cy={cy}
          r={R}
          fill="none"
          stroke={theme === 'dark' ? '#1c2d48' : '#ccd9f5'}
          strokeWidth="9"
        />
        {/* Progress */}
        <circle
          ref={circleRef}
          cx={cx}
          cy={cy}
          r={R}
          fill="none"
          stroke={color}
          strokeWidth="9"
          strokeLinecap="round"
          strokeDasharray={CIRCUMFERENCE}
          strokeDashoffset={CIRCUMFERENCE}
          transform={`rotate(-90 ${cx} ${cy})`}
          style={{ filter: `drop-shadow(0 0 6px ${color}60)` }}
        />
        {/* Score text */}
        <text
          x={cx}
          y={cy - 6}
          textAnchor="middle"
          fill={theme === 'dark' ? 'white' : '#0f172a'}
          fontSize="26"
          fontWeight="700"
          fontFamily="'JetBrains Mono', monospace"
        >
          {clampedScore}
        </text>
        <text
          x={cx}
          y={cy + 14}
          textAnchor="middle"
          fill={theme === 'dark' ? '#9ca3af' : '#64748b'}
          fontSize="10"
          fontFamily="Inter, sans-serif"
        >
          / 100
        </text>
      </svg>
      <span className="text-xs text-gray-500 font-mono">{label}</span>
    </div>
  )
}
