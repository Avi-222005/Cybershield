import React, { useCallback, useEffect, useState } from 'react'
import { useOutletContext } from 'react-router-dom'
import type { NetworkMonitorContextType } from './NetworkMonitorLayout'
import type { SecurityAlert, AlertsSummary } from '../../types/networkMonitor'
import {
  getAlerts,
  getAlertsSummary,
  acknowledgeAlert,
  investigateAlert,
  resolveAlert,
  markAlertFalsePositive,
} from '../../services/networkMonitorService'
import { AlertSummaryCards } from '../../components/network-monitor/alerts/AlertSummaryCards'
import { AlertFilters } from '../../components/network-monitor/alerts/AlertFilters'
import { AlertTable } from '../../components/network-monitor/alerts/AlertTable'
import { AlertDetailDrawer } from '../../components/network-monitor/alerts/AlertDetailDrawer'
import { ShieldAlert, RefreshCw, Info, ShieldCheck } from 'lucide-react'

export default function Alerts() {
  const { summary } = useOutletContext<NetworkMonitorContextType>()
  const agentState = summary?.status.state || 'STOPPED'
  const isRunning = agentState === 'RUNNING'

  const [alerts, setAlerts] = useState<SecurityAlert[]>([])
  const [alertsSummary, setAlertsSummary] = useState<AlertsSummary | null>(null)
  const [selectedAlert, setSelectedAlert] = useState<SecurityAlert | null>(null)
  const [isDrawerOpen, setIsDrawerOpen] = useState(false)
  const [isLoading, setIsLoading] = useState(true)

  // Filters
  const [search, setSearch] = useState('')
  const [severity, setSeverity] = useState('ALL')
  const [status, setStatus] = useState('ALL')
  const [category, setCategory] = useState('ALL')

  const fetchAlertsData = useCallback(async () => {
    try {
      const [alertsRes, summaryRes] = await Promise.all([
        getAlerts({
          search,
          severity,
          status,
          category,
          limit: 100,
        }),
        getAlertsSummary(),
      ])

      if (alertsRes.success) {
        setAlerts(alertsRes.alerts)
      }
      if (summaryRes.success) {
        setAlertsSummary(summaryRes.summary)
      }
    } catch (err: any) {
      console.warn('Failed to fetch alerts:', err?.message)
    } finally {
      setIsLoading(false)
    }
  }, [search, severity, status, category])

  // Initial fetch and poll
  useEffect(() => {
    fetchAlertsData()
    const timer = setInterval(() => {
      if (document.visibilityState === 'visible' && isRunning) {
        fetchAlertsData()
      }
    }, 2000)
    return () => clearInterval(timer)
  }, [fetchAlertsData, isRunning])

  const handleSelectAlert = (alert: SecurityAlert) => {
    setSelectedAlert(alert)
    setIsDrawerOpen(true)
  }

  const handleAcknowledge = async (alertId: string) => {
    try {
      const res = await acknowledgeAlert(alertId)
      if (res.success && res.alert) {
        setSelectedAlert(res.alert)
        await fetchAlertsData()
      }
    } catch (err: any) {
      console.error('Acknowledge failed:', err?.message)
    }
  }

  const handleInvestigate = async (alertId: string, notes?: string) => {
    try {
      const res = await investigateAlert(alertId, notes)
      if (res.success && res.alert) {
        setSelectedAlert(res.alert)
        await fetchAlertsData()
      }
    } catch (err: any) {
      console.error('Investigate failed:', err?.message)
    }
  }

  const handleResolve = async (alertId: string, notes?: string) => {
    try {
      const res = await resolveAlert(alertId, notes)
      if (res.success && res.alert) {
        setSelectedAlert(res.alert)
        await fetchAlertsData()
      }
    } catch (err: any) {
      console.error('Resolve failed:', err?.message)
    }
  }

  const handleFalsePositive = async (alertId: string, reason?: string) => {
    try {
      const res = await markAlertFalsePositive(alertId, reason)
      if (res.success && res.alert) {
        setSelectedAlert(res.alert)
        await fetchAlertsData()
      }
    } catch (err: any) {
      console.error('False positive mark failed:', err?.message)
    }
  }

  const handleResetFilters = () => {
    setSearch('')
    setSeverity('ALL')
    setStatus('ALL')
    setCategory('ALL')
  }

  return (
    <div className="space-y-6">
      {/* Disclaimer / Guidance Banner */}
      <div className="glass-card rounded-2xl border border-cyber-border p-4 flex items-start gap-3 text-xs font-mono">
        <Info size={16} className="text-[#0d6efd] flex-shrink-0 mt-0.5" />
        <div className="space-y-1 text-gray-300">
          <p>
            <strong>In-Memory Detection Telemetry: </strong>
            Threat indicators are passively identified from real-time network metadata using 5 heuristic rules.
            No persistent database storage and no packet payloads are retained.
          </p>
          <p className="text-gray-400">
            Indicators represent statistical and behavioural anomalies requiring analyst verification, not confirmed host compromise.
          </p>
        </div>
      </div>

      {/* Severity Cards */}
      <AlertSummaryCards
        summary={alertsSummary}
        activeSeverityFilter={severity}
        onSelectSeverity={(sev) => setSeverity(sev)}
      />

      {/* Filters and Controls */}
      <AlertFilters
        search={search}
        onSearchChange={setSearch}
        severity={severity}
        onSeverityChange={setSeverity}
        status={status}
        onStatusChange={setStatus}
        category={category}
        onCategoryChange={setCategory}
        onReset={handleResetFilters}
      />

      {/* Alerts Table */}
      <div className="space-y-2">
        <div className="flex items-center justify-between px-1">
          <span className="text-xs font-mono text-gray-400">
            Showing {alerts.length} indicator{alerts.length !== 1 ? 's' : ''}
          </span>
          <button
            type="button"
            onClick={fetchAlertsData}
            className="inline-flex items-center gap-1.5 text-xs font-mono text-gray-400 hover:text-white transition-colors"
          >
            <RefreshCw size={12} className={isLoading ? 'animate-spin' : ''} />
            <span>Refresh</span>
          </button>
        </div>

        <AlertTable
          alerts={alerts}
          onSelectAlert={handleSelectAlert}
          onAcknowledgeAlert={handleAcknowledge}
        />
      </div>

      {/* Slide-out Detail Drawer */}
      <AlertDetailDrawer
        alert={selectedAlert}
        isOpen={isDrawerOpen}
        onClose={() => setIsDrawerOpen(false)}
        onAcknowledge={handleAcknowledge}
        onInvestigate={handleInvestigate}
        onResolve={handleResolve}
        onFalsePositive={handleFalsePositive}
      />
    </div>
  )
}
