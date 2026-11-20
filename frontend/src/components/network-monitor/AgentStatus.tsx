import React from 'react'
import type { AgentState } from '../../types/networkMonitor'
import { cn } from '../../lib/utils'
import { Activity, AlertCircle, AlertTriangle, CheckCircle2, PauseCircle, RefreshCw } from 'lucide-react'

interface AgentStatusProps {
  state: AgentState
  showIcon?: boolean
  className?: string
}

export function AgentStatus({ state, showIcon = true, className }: AgentStatusProps) {
  const config = {
    RUNNING: {
      label: 'RUNNING',
      color: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30',
      dot: 'bg-emerald-400 shadow-[0_0_8px_#10b981]',
      icon: Activity,
    },
    STOPPED: {
      label: 'STOPPED',
      color: 'text-gray-400 bg-gray-500/10 border-gray-500/30',
      dot: 'bg-gray-400',
      icon: PauseCircle,
    },
    INITIALIZING: {
      label: 'INITIALIZING',
      color: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
      dot: 'bg-amber-400',
      icon: RefreshCw,
    },
    STOPPING: {
      label: 'STOPPING',
      color: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
      dot: 'bg-amber-400',
      icon: RefreshCw,
    },
    ERROR: {
      label: 'ERROR',
      color: 'text-red-400 bg-red-500/10 border-red-500/30',
      dot: 'bg-red-400 shadow-[0_0_8px_#ef4444]',
      icon: AlertCircle,
    },
    DEGRADED: {
      label: 'DEGRADED',
      color: 'text-orange-400 bg-orange-500/10 border-orange-500/30',
      dot: 'bg-orange-400',
      icon: AlertTriangle,
    },
  }[state] || {
    label: state,
    color: 'text-gray-400 bg-gray-500/10 border-gray-500/30',
    dot: 'bg-gray-400',
    icon: Activity,
  }

  const Icon = config.icon

  return (
    <div
      className={cn(
        'inline-flex items-center gap-2 px-2.5 py-1 rounded-full text-xs font-mono font-medium border transition-colors',
        config.color,
        className
      )}
    >
      <span className="relative flex h-2 w-2">
        {state === 'RUNNING' && (
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
        )}
        <span className={cn('relative inline-flex rounded-full h-2 w-2', config.dot)} />
      </span>
      {showIcon && <Icon size={12} className={cn(state === 'INITIALIZING' && 'animate-spin')} />}
      <span>{config.label}</span>
    </div>
  )
}
export default AgentStatus
