import { ShieldCheck, ShieldAlert, ShieldX, Shield } from 'lucide-react'
import { cn } from '../../lib/utils'

interface ResultBadgeProps {
  verdict: string
  size?: 'sm' | 'md' | 'lg'
  className?: string
}

const config = {
  SAFE: {
    label: 'Safe',
    color: 'text-green-400',
    bg: 'bg-green-500/10',
    border: 'border-green-500/30',
    icon: ShieldCheck,
    glow: 'shadow-[0_0_20px_rgba(34,197,94,0.15)]',
  },
  CLEAN: {
    label: 'Clean',
    color: 'text-green-400',
    bg: 'bg-green-500/10',
    border: 'border-green-500/30',
    icon: ShieldCheck,
    glow: 'shadow-[0_0_20px_rgba(34,197,94,0.15)]',
  },
  SUSPICIOUS: {
    label: 'Suspicious',
    color: 'text-yellow-400',
    bg: 'bg-yellow-500/10',
    border: 'border-yellow-500/30',
    icon: ShieldAlert,
    glow: 'shadow-[0_0_20px_rgba(245,158,11,0.15)]',
  },
  MALICIOUS: {
    label: 'Malicious',
    color: 'text-red-400',
    bg: 'bg-red-500/10',
    border: 'border-red-500/30',
    icon: ShieldX,
    glow: 'shadow-[0_0_20px_rgba(239,68,68,0.15)]',
  },
} as const

const sizes = {
  sm: { container: 'px-2.5 py-1 text-xs gap-1.5', icon: 14 },
  md: { container: 'px-4 py-2 text-sm gap-2', icon: 16 },
  lg: { container: 'px-5 py-2.5 text-base gap-2.5', icon: 20 },
}

export default function ResultBadge({ verdict, size = 'md', className }: ResultBadgeProps) {
  const key = verdict?.toUpperCase() as keyof typeof config
  const cfg = config[key] ?? {
    label: verdict ?? 'Unknown',
    color: 'text-gray-400',
    bg: 'bg-gray-500/10',
    border: 'border-gray-500/30',
    icon: Shield,
    glow: '',
  }
  const sz = sizes[size]
  const Icon = cfg.icon

  return (
    <span
      className={cn(
        'inline-flex items-center rounded-full border font-semibold font-mono',
        cfg.color,
        cfg.bg,
        cfg.border,
        cfg.glow,
        sz.container,
        className,
      )}
    >
      <Icon size={sz.icon} />
      {cfg.label}
    </span>
  )
}
