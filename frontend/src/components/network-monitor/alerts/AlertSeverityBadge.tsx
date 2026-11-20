import React from 'react'
import type { AlertSeverity, AlertStatus } from '../../../types/networkMonitor'
import { ShieldAlert, AlertTriangle, Info, ShieldCheck, CheckCircle2 } from 'lucide-react'
import { cn } from '../../../lib/utils'

interface AlertSeverityBadgeProps {
  severity: AlertSeverity | string
  className?: string
  showIcon?: boolean
}

export function AlertSeverityBadge({ severity, className, showIcon = true }: AlertSeverityBadgeProps) {
  const sev = (severity || 'LOW').toUpperCase()

  const config = {
    CRITICAL: {
      label: 'CRITICAL',
      bg: 'bg-red-500/15 text-red-400 border-red-500/30',
      icon: ShieldAlert,
    },
    HIGH: {
      label: 'HIGH',
      bg: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
      icon: AlertTriangle,
    },
    MEDIUM: {
      label: 'MEDIUM',
      bg: 'bg-yellow-500/15 text-yellow-300 border-yellow-500/30',
      icon: Info,
    },
    LOW: {
      label: 'LOW',
      bg: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
      icon: Info,
    },
  }[sev] || {
    label: sev,
    bg: 'bg-gray-500/15 text-gray-400 border-gray-500/30',
    icon: Info,
  }

  const Icon = config.icon

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-mono font-semibold border',
        config.bg,
        className
      )}
    >
      {showIcon && <Icon size={12} />}
      <span>{config.label}</span>
    </span>
  )
}

interface AlertStatusBadgeProps {
  status: AlertStatus | string
  className?: string
}

export function AlertStatusBadge({ status, className }: AlertStatusBadgeProps) {
  const st = (status || 'NEW').toUpperCase()

  const config = {
    NEW: {
      label: 'NEW',
      bg: 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30',
    },
    ACKNOWLEDGED: {
      label: 'ACKNOWLEDGED',
      bg: 'bg-purple-500/15 text-purple-400 border-purple-500/30',
    },
    INVESTIGATING: {
      label: 'INVESTIGATING',
      bg: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
    },
    RESOLVED: {
      label: 'RESOLVED',
      bg: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
    },
    FALSE_POSITIVE: {
      label: 'FALSE POSITIVE',
      bg: 'bg-gray-500/15 text-gray-400 border-gray-500/30',
    },
  }[st] || {
    label: st,
    bg: 'bg-gray-500/15 text-gray-400 border-gray-500/30',
  }

  return (
    <span
      className={cn(
        'inline-flex items-center px-2 py-0.5 rounded-md text-[11px] font-mono font-medium border',
        config.bg,
        className
      )}
    >
      {config.label}
    </span>
  )
}
