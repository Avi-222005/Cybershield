import React, { ElementType } from 'react'
import { cn } from '../../lib/utils'

interface NetworkStatCardProps {
  label: string
  value: string | number
  unit?: string
  secondary?: string
  icon: ElementType
  iconColor?: string
  trend?: 'up' | 'down' | 'neutral'
  className?: string
}

export function NetworkStatCard({
  label,
  value,
  unit,
  secondary,
  icon: Icon,
  iconColor = 'text-[#0d6efd]',
  className,
}: NetworkStatCardProps) {
  return (
    <div
      className={cn(
        'glass-card rounded-xl p-4 sm:p-5 border border-cyber-border transition-all duration-200 hover:border-[#0d6efd]/40 flex flex-col justify-between relative overflow-hidden group',
        className
      )}
    >
      <div className="flex items-center justify-between mb-3">
        <span className="text-xs sm:text-sm font-medium text-gray-400 tracking-wide">{label}</span>
        <div className={cn('p-2 rounded-lg bg-cyber-surface/60 border border-cyber-border/40', iconColor)}>
          <Icon size={18} />
        </div>
      </div>

      <div className="flex items-baseline gap-1.5">
        <span className="text-2xl sm:text-3xl font-bold font-mono text-gray-900 dark:text-white tracking-tight">
          {value}
        </span>
        {unit && <span className="text-xs sm:text-sm font-mono text-gray-400">{unit}</span>}
      </div>

      {secondary && (
        <div className="mt-2 pt-2 border-t border-cyber-border/30 text-[11px] sm:text-xs text-gray-400 flex items-center justify-between">
          <span>{secondary}</span>
        </div>
      )}
    </div>
  )
}
export default NetworkStatCard
