import React, { ElementType } from 'react'
import { Activity, Play, RefreshCw } from 'lucide-react'
import { cn } from '../../lib/utils'

interface NetworkEmptyStateProps {
  title?: string
  description?: string
  icon?: ElementType
  actionLabel?: string
  onAction?: () => void
  isActionLoading?: boolean
  className?: string
}

export function NetworkEmptyState({
  title = 'Monitoring is Stopped',
  description = 'Start the network monitoring agent to capture real-time bandwidth, active connections, and packet telemetry.',
  icon: Icon = Activity,
  actionLabel = 'Start Monitoring',
  onAction,
  isActionLoading = false,
  className,
}: NetworkEmptyStateProps) {
  return (
    <div
      className={cn(
        'glass-card rounded-2xl border border-cyber-border p-8 sm:p-12 text-center flex flex-col items-center justify-center max-w-lg mx-auto my-6',
        className
      )}
    >
      <div className="w-14 h-14 rounded-2xl bg-[#0d6efd]/10 border border-[#0d6efd]/30 text-[#0d6efd] flex items-center justify-center mb-4 shadow-[0_0_20px_rgba(13,110,253,0.15)]">
        <Icon size={28} />
      </div>

      <h3 className="text-lg sm:text-xl font-bold text-gray-900 dark:text-white mb-2">{title}</h3>
      <p className="text-sm text-gray-400 max-w-sm mb-6 leading-relaxed">{description}</p>

      {onAction && (
        <button
          onClick={onAction}
          disabled={isActionLoading}
          className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-[#0d6efd] hover:bg-[#0b5ed7] text-white text-sm font-semibold transition-all shadow-[0_0_15px_rgba(13,110,253,0.3)] disabled:opacity-50"
        >
          {isActionLoading ? (
            <>
              <RefreshCw size={16} className="animate-spin" />
              <span>Starting Agent...</span>
            </>
          ) : (
            <>
              <Play size={16} className="fill-white" />
              <span>{actionLabel}</span>
            </>
          )}
        </button>
      )}
    </div>
  )
}
export default NetworkEmptyState
