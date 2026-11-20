import React from 'react'
import type { AlertsSummary } from '../../../types/networkMonitor'
import { ShieldAlert, AlertTriangle, AlertCircle, CheckCircle2, ShieldQuestion } from 'lucide-react'
import { cn } from '../../../lib/utils'

interface AlertSummaryCardsProps {
  summary: AlertsSummary | null
  activeSeverityFilter?: string
  onSelectSeverity?: (severity: string) => void
}

export function AlertSummaryCards({
  summary,
  activeSeverityFilter = 'ALL',
  onSelectSeverity,
}: AlertSummaryCardsProps) {
  const cards = [
    {
      key: 'ALL',
      title: 'Total Indicators',
      count: summary?.total || 0,
      icon: ShieldAlert,
      color: 'text-cyber-blue',
      glow: 'shadow-[0_0_20px_rgba(13,110,253,0.15)]',
      border: 'border-cyber-border',
      activeBorder: 'border-cyber-blue ring-1 ring-cyber-blue',
    },
    {
      key: 'CRITICAL',
      title: 'Critical',
      count: summary?.critical || 0,
      icon: ShieldAlert,
      color: 'text-red-400',
      glow: 'shadow-[0_0_20px_rgba(239,68,68,0.15)]',
      border: 'border-red-500/20',
      activeBorder: 'border-red-500 ring-1 ring-red-500',
    },
    {
      key: 'HIGH',
      title: 'High',
      count: summary?.high || 0,
      icon: AlertTriangle,
      color: 'text-amber-400',
      glow: 'shadow-[0_0_20px_rgba(245,158,11,0.15)]',
      border: 'border-amber-500/20',
      activeBorder: 'border-amber-500 ring-1 ring-amber-500',
    },
    {
      key: 'MEDIUM',
      title: 'Medium',
      count: summary?.medium || 0,
      icon: AlertCircle,
      color: 'text-yellow-400',
      glow: 'shadow-[0_0_20px_rgba(234,179,8,0.15)]',
      border: 'border-yellow-500/20',
      activeBorder: 'border-yellow-500 ring-1 ring-yellow-500',
    },
    {
      key: 'LOW',
      title: 'Low / Info',
      count: summary?.low || 0,
      icon: ShieldQuestion,
      color: 'text-blue-400',
      glow: 'shadow-[0_0_20px_rgba(59,130,246,0.15)]',
      border: 'border-blue-500/20',
      activeBorder: 'border-blue-500 ring-1 ring-blue-500',
    },
  ]

  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3.5">
      {cards.map((c) => {
        const Icon = c.icon
        const isSelected = activeSeverityFilter.toUpperCase() === c.key
        return (
          <button
            key={c.key}
            type="button"
            onClick={() => onSelectSeverity && onSelectSeverity(c.key)}
            className={cn(
              'glass-card rounded-2xl p-4 text-left transition-all duration-200 cursor-pointer relative overflow-hidden group',
              c.border,
              isSelected ? c.activeBorder : 'hover:border-cyber-border/80'
            )}
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-medium text-gray-400">{c.title}</span>
              <div
                className={cn(
                  'w-7 h-7 rounded-lg flex items-center justify-center bg-cyber-surface/60 border border-cyber-border/40',
                  c.color
                )}
              >
                <Icon size={14} />
              </div>
            </div>
            <div className="flex items-baseline gap-1.5">
              <span className="text-2xl font-extrabold font-mono text-gray-900 dark:text-white">
                {c.count}
              </span>
              {c.key === 'ALL' && summary && (
                <span className="text-[11px] font-mono text-gray-400">
                  ({summary.new} new)
                </span>
              )}
            </div>
          </button>
        )
      })}
    </div>
  )
}
