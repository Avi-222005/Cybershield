import React from 'react'
import type { SecurityAlert } from '../../../types/networkMonitor'
import { AlertSeverityBadge, AlertStatusBadge } from './AlertSeverityBadge'
import {
  ShieldAlert,
  ArrowRight,
  ExternalLink,
  CheckCircle,
  Eye,
  ShieldCheck,
  Clock,
} from 'lucide-react'
import { cn } from '../../../lib/utils'

interface AlertTableProps {
  alerts: SecurityAlert[]
  onSelectAlert: (alert: SecurityAlert) => void
  onAcknowledgeAlert?: (alertId: string) => Promise<void>
  className?: string
}

export function AlertTable({
  alerts,
  onSelectAlert,
  onAcknowledgeAlert,
  className,
}: AlertTableProps) {
  const formatTime = (ts?: number) => {
    if (!ts) return '-'
    const d = new Date(ts * 1000)
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
  }

  if (alerts.length === 0) {
    return (
      <div className={cn('glass-card rounded-2xl border border-cyber-border p-12 text-center', className)}>
        <div className="w-12 h-12 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 flex items-center justify-center mx-auto mb-3 shadow-[0_0_20px_rgba(16,185,129,0.15)]">
          <ShieldCheck size={24} />
        </div>
        <h3 className="text-base font-bold text-gray-900 dark:text-white mb-1">
          No Security Indicators Detected
        </h3>
        <p className="text-xs text-gray-400 max-w-md mx-auto">
          Threat detection rules have evaluated recent traffic metadata and found no anomalous port scans, suspicious DNS queries, or outbound anomalies.
        </p>
      </div>
    )
  }

  return (
    <div className={cn('glass-card rounded-2xl border border-cyber-border overflow-hidden', className)}>
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs font-mono">
          <thead className="bg-cyber-surface/70 border-b border-cyber-border/40 text-gray-400 uppercase text-[11px] tracking-wider">
            <tr>
              <th className="py-3 px-4">Severity</th>
              <th className="py-3 px-4">Indicator / Rule</th>
              <th className="py-3 px-4">Endpoints</th>
              <th className="py-3 px-4">Occurrences</th>
              <th className="py-3 px-4">Last Seen</th>
              <th className="py-3 px-4">Status</th>
              <th className="py-3 px-4 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-cyber-border/20 text-gray-300">
            {alerts.map((alert) => (
              <tr
                key={alert.alert_id}
                className="hover:bg-cyber-surface/40 transition-colors group cursor-pointer"
                onClick={() => onSelectAlert(alert)}
              >
                {/* Severity */}
                <td className="py-3 px-4 whitespace-nowrap">
                  <AlertSeverityBadge severity={alert.severity} />
                </td>

                {/* Title & Category */}
                <td className="py-3 px-4">
                  <div className="font-sans font-bold text-gray-100 group-hover:text-[#0d6efd] transition-colors">
                    {alert.title}
                  </div>
                  <div className="text-[11px] font-mono text-gray-500 flex items-center gap-1.5 mt-0.5">
                    <span>{alert.category}</span>
                    <span>•</span>
                    <span>conf: {Math.round(alert.confidence * 100)}%</span>
                  </div>
                </td>

                {/* Endpoints */}
                <td className="py-3 px-4 whitespace-nowrap">
                  <div className="flex items-center gap-1.5">
                    <span className="text-gray-300">{alert.source_ip || 'Host'}</span>
                    <ArrowRight size={12} className="text-gray-500" />
                    <span className="text-white font-medium">
                      {alert.destination_ip || 'Any'}
                      {alert.destination_ports && alert.destination_ports.length > 0 && (
                        <span className="text-[#0d6efd] ml-1">
                          :{alert.destination_ports[0]}
                          {alert.destination_ports.length > 1 ? ` (+${alert.destination_ports.length - 1})` : ''}
                        </span>
                      )}
                    </span>
                  </div>
                  {alert.process_name && (
                    <div className="text-[10px] text-gray-500 mt-0.5">
                      proc: {alert.process_name}
                    </div>
                  )}
                </td>

                {/* Occurrences */}
                <td className="py-3 px-4 whitespace-nowrap">
                  <span className="px-2 py-0.5 rounded bg-cyber-surface/60 border border-cyber-border/40 font-mono text-[11px] text-gray-300">
                    x{alert.occurrence_count}
                  </span>
                </td>

                {/* Last Seen */}
                <td className="py-3 px-4 whitespace-nowrap text-gray-400">
                  <span title={new Date(alert.last_seen * 1000).toLocaleString()}>
                    {formatTime(alert.last_seen)}
                  </span>
                </td>

                {/* Status */}
                <td className="py-3 px-4 whitespace-nowrap">
                  <AlertStatusBadge status={alert.status} />
                </td>

                {/* Actions */}
                <td className="py-3 px-4 whitespace-nowrap text-right" onClick={(e) => e.stopPropagation()}>
                  <div className="flex items-center justify-end gap-1.5">
                    {alert.status === 'NEW' && onAcknowledgeAlert && (
                      <button
                        type="button"
                        onClick={() => onAcknowledgeAlert(alert.alert_id)}
                        className="p-1.5 rounded-lg bg-purple-500/10 hover:bg-purple-500/20 text-purple-300 border border-purple-500/30 transition-colors"
                        title="Quick Acknowledge"
                      >
                        <CheckCircle size={14} />
                      </button>
                    )}
                    <button
                      type="button"
                      onClick={() => onSelectAlert(alert)}
                      className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-cyber-surface/80 hover:bg-cyber-surface text-gray-300 hover:text-white border border-cyber-border/60 transition-colors text-[11px]"
                    >
                      <Eye size={12} />
                      <span>Inspect</span>
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
