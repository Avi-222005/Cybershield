import React, { useState } from 'react'
import type { SecurityAlert, AlertStatus } from '../../../types/networkMonitor'
import { AlertSeverityBadge, AlertStatusBadge } from './AlertSeverityBadge'
import {
  X,
  ShieldAlert,
  ArrowRight,
  Clock,
  Activity,
  Layers,
  FileText,
  CheckCircle,
  HelpCircle,
  AlertTriangle,
  Send,
  Eye,
} from 'lucide-react'
import { cn } from '../../../lib/utils'

interface AlertDetailDrawerProps {
  alert: SecurityAlert | null
  isOpen: boolean
  onClose: () => void
  onAcknowledge: (alertId: string) => Promise<void>
  onInvestigate: (alertId: string, notes?: string) => Promise<void>
  onResolve: (alertId: string, notes?: string) => Promise<void>
  onFalsePositive: (alertId: string, reason?: string) => Promise<void>
}

export function AlertDetailDrawer({
  alert,
  isOpen,
  onClose,
  onAcknowledge,
  onInvestigate,
  onResolve,
  onFalsePositive,
}: AlertDetailDrawerProps) {
  const [actionNotes, setActionNotes] = useState('')
  const [activeAction, setActiveAction] = useState<'investigate' | 'resolve' | 'false_positive' | null>(null)
  const [isSubmitting, setIsSubmitting] = useState(false)

  if (!isOpen || !alert) return null

  const formatTimestamp = (ts?: number) => {
    if (!ts) return '-'
    const d = new Date(ts * 1000)
    return d.toLocaleString()
  }

  const handleActionSubmit = async () => {
    if (!activeAction) return
    setIsSubmitting(true)
    try {
      if (activeAction === 'investigate') {
        await onInvestigate(alert.alert_id, actionNotes)
      } else if (activeAction === 'resolve') {
        await onResolve(alert.alert_id, actionNotes)
      } else if (activeAction === 'false_positive') {
        await onFalsePositive(alert.alert_id, actionNotes)
      }
      setActiveAction(null)
      setActionNotes('')
    } finally {
      setIsSubmitting(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="w-full max-w-2xl bg-cyber-bg border-l border-cyber-border h-full overflow-y-auto p-6 flex flex-col justify-between shadow-2xl">
        {/* Header */}
        <div>
          <div className="flex items-start justify-between pb-4 border-b border-cyber-border/40">
            <div className="space-y-1.5">
              <div className="flex items-center gap-2 flex-wrap">
                <AlertSeverityBadge severity={alert.severity} />
                <AlertStatusBadge status={alert.status} />
                <span className="text-xs font-mono text-gray-500 bg-cyber-surface/60 px-2 py-0.5 rounded border border-cyber-border/40">
                  {alert.category}
                </span>
              </div>
              <h2 className="text-xl font-bold text-gray-900 dark:text-white mt-1">
                {alert.title}
              </h2>
              <p className="text-xs font-mono text-gray-500">ID: {alert.alert_id}</p>
            </div>
            <button
              onClick={onClose}
              className="p-1.5 text-gray-400 hover:text-white rounded-lg hover:bg-cyber-surface/60 transition-colors"
            >
              <X size={20} />
            </button>
          </div>

          {/* Description & Detection Indicator Banner */}
          <div className="my-5 p-3.5 rounded-xl bg-blue-500/10 border border-blue-500/20 text-xs text-blue-300">
            <div className="flex items-start gap-2">
              <ShieldAlert size={16} className="text-[#0d6efd] flex-shrink-0 mt-0.5" />
              <div>
                <span className="font-semibold text-white">Detection Indicator: </span>
                <span>{alert.reason}</span>
              </div>
            </div>
          </div>

          <div className="space-y-5">
            {/* Confidence & Frequency */}
            <div className="grid grid-cols-2 gap-3">
              <div className="glass-card rounded-xl p-3 border border-cyber-border/60">
                <span className="text-[11px] font-mono text-gray-400">Confidence Score</span>
                <div className="flex items-center gap-2 mt-1">
                  <div className="flex-1 bg-cyber-surface rounded-full h-2 overflow-hidden border border-cyber-border/40">
                    <div
                      className="bg-[#0d6efd] h-full rounded-full transition-all"
                      style={{ width: `${Math.round(alert.confidence * 100)}%` }}
                    />
                  </div>
                  <span className="text-xs font-mono font-bold text-white">
                    {Math.round(alert.confidence * 100)}%
                  </span>
                </div>
              </div>

              <div className="glass-card rounded-xl p-3 border border-cyber-border/60">
                <span className="text-[11px] font-mono text-gray-400">Occurrences</span>
                <div className="text-sm font-bold font-mono text-white mt-1">
                  {alert.occurrence_count} time{alert.occurrence_count > 1 ? 's' : ''}
                </div>
              </div>
            </div>

            {/* Network Endpoints */}
            <div className="glass-card rounded-xl p-4 border border-cyber-border/60 space-y-3">
              <h3 className="text-xs font-bold text-gray-300 uppercase tracking-wider font-mono">
                Network Endpoints
              </h3>
              <div className="flex items-center justify-between text-xs font-mono bg-cyber-surface/50 p-3 rounded-lg border border-cyber-border/40">
                <div>
                  <span className="text-gray-500 block text-[10px]">Source</span>
                  <span className="text-white font-semibold">{alert.source_ip || 'Local Host'}</span>
                </div>
                <ArrowRight size={16} className="text-[#0d6efd]" />
                <div className="text-right">
                  <span className="text-gray-500 block text-[10px]">Destination</span>
                  <span className="text-white font-semibold">
                    {alert.destination_ip || 'Multiple / Any'}
                    {alert.destination_ports && alert.destination_ports.length > 0 && (
                      <span className="text-[#0d6efd] ml-1">
                        :{alert.destination_ports.slice(0, 3).join(', ')}
                        {alert.destination_ports.length > 3 ? '...' : ''}
                      </span>
                    )}
                  </span>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                <div className="bg-cyber-surface/30 p-2 rounded border border-cyber-border/30">
                  <span className="text-gray-500 block text-[10px]">Protocol</span>
                  <span className="text-gray-200">{alert.protocol?.toUpperCase() || 'TCP/UDP'}</span>
                </div>
                <div className="bg-cyber-surface/30 p-2 rounded border border-cyber-border/30">
                  <span className="text-gray-500 block text-[10px]">Associated Process</span>
                  <span className="text-gray-200">{alert.process_name || 'System / Unattributed'}</span>
                </div>
              </div>
            </div>

            {/* Evidence Telemetry */}
            {alert.evidence && Object.keys(alert.evidence).length > 0 && (
              <div className="glass-card rounded-xl p-4 border border-cyber-border/60 space-y-2">
                <h3 className="text-xs font-bold text-gray-300 uppercase tracking-wider font-mono">
                  Telemetry Evidence
                </h3>
                <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                  {Object.entries(alert.evidence).map(([key, value]) => (
                    <div
                      key={key}
                      className="bg-cyber-surface/40 p-2 rounded border border-cyber-border/30"
                    >
                      <span className="text-gray-400 block text-[10px] capitalize">
                        {key.replace(/_/g, ' ')}
                      </span>
                      <span className="text-cyber-blue font-medium break-all">
                        {Array.isArray(value)
                          ? value.slice(0, 5).join(', ') + (value.length > 5 ? '...' : '')
                          : typeof value === 'object' && value !== null
                          ? JSON.stringify(value)
                          : String(value)}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Timestamps */}
            <div className="flex items-center justify-between text-xs font-mono text-gray-400 px-1">
              <span>First seen: {formatTimestamp(alert.first_seen)}</span>
              <span>Last seen: {formatTimestamp(alert.last_seen)}</span>
            </div>

            {/* Notes / False Positive Reason */}
            {alert.notes && (
              <div className="p-3 rounded-lg bg-cyber-surface/50 border border-cyber-border/40 text-xs">
                <span className="text-gray-400 font-mono block mb-1">Analyst Notes:</span>
                <p className="text-gray-200">{alert.notes}</p>
              </div>
            )}
            {alert.false_positive_reason && (
              <div className="p-3 rounded-lg bg-gray-500/10 border border-gray-500/30 text-xs">
                <span className="text-gray-400 font-mono block mb-1">False Positive Rationale:</span>
                <p className="text-gray-300">{alert.false_positive_reason}</p>
              </div>
            )}
          </div>
        </div>

        {/* Footer Actions */}
        <div className="pt-6 border-t border-cyber-border/40 space-y-3 mt-6">
          {activeAction ? (
            <div className="space-y-2 p-3 rounded-xl bg-cyber-surface/70 border border-cyber-border">
              <label className="text-xs font-mono text-gray-300 block capitalize">
                {activeAction === 'false_positive' ? 'False Positive Rationale' : `${activeAction} Notes`}
              </label>
              <textarea
                value={actionNotes}
                onChange={(e) => setActionNotes(e.target.value)}
                rows={2}
                placeholder={
                  activeAction === 'false_positive'
                    ? 'Explain why this pattern is benign (e.g., scheduled backup task, known dev server)...'
                    : 'Add technical remarks or findings...'
                }
                className="w-full p-2.5 rounded-lg bg-cyber-bg border border-cyber-border text-xs text-white placeholder-gray-500 font-mono focus:outline-none focus:border-[#0d6efd]"
              />
              <div className="flex items-center justify-end gap-2">
                <button
                  type="button"
                  onClick={() => {
                    setActiveAction(null)
                    setActionNotes('')
                  }}
                  className="px-3 py-1.5 rounded-lg text-xs font-mono text-gray-400 hover:text-white transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={handleActionSubmit}
                  disabled={isSubmitting}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#0d6efd] hover:bg-[#0b5ed7] text-white text-xs font-mono font-medium transition-colors disabled:opacity-50"
                >
                  <Send size={12} />
                  <span>{isSubmitting ? 'Saving...' : 'Confirm'}</span>
                </button>
              </div>
            </div>
          ) : (
            <div className="flex flex-wrap items-center gap-2">
              {alert.status === 'NEW' && (
                <button
                  type="button"
                  onClick={() => onAcknowledge(alert.alert_id)}
                  className="flex-1 inline-flex items-center justify-center gap-1.5 px-3.5 py-2 rounded-xl bg-purple-500/15 hover:bg-purple-500/25 border border-purple-500/30 text-purple-300 text-xs font-mono font-medium transition-colors"
                >
                  <CheckCircle size={14} />
                  <span>Acknowledge</span>
                </button>
              )}

              {alert.status !== 'RESOLVED' && alert.status !== 'FALSE_POSITIVE' && (
                <>
                  <button
                    type="button"
                    onClick={() => setActiveAction('investigate')}
                    className="flex-1 inline-flex items-center justify-center gap-1.5 px-3.5 py-2 rounded-xl bg-amber-500/15 hover:bg-amber-500/25 border border-amber-500/30 text-amber-300 text-xs font-mono font-medium transition-colors"
                  >
                    <Eye size={14} />
                    <span>Investigate</span>
                  </button>

                  <button
                    type="button"
                    onClick={() => setActiveAction('resolve')}
                    className="flex-1 inline-flex items-center justify-center gap-1.5 px-3.5 py-2 rounded-xl bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-500/30 text-emerald-300 text-xs font-mono font-medium transition-colors"
                  >
                    <CheckCircle size={14} />
                    <span>Resolve</span>
                  </button>
                </>
              )}

              {alert.status !== 'FALSE_POSITIVE' && (
                <button
                  type="button"
                  onClick={() => setActiveAction('false_positive')}
                  className="inline-flex items-center justify-center gap-1.5 px-3.5 py-2 rounded-xl bg-gray-500/15 hover:bg-gray-500/25 border border-gray-500/30 text-gray-300 text-xs font-mono transition-colors"
                >
                  <HelpCircle size={14} />
                  <span>Mark False Positive</span>
                </button>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
