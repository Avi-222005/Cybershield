import React from 'react'
import { Link, NavLink, Outlet, useLocation } from 'react-router-dom'
import PageWrapper from '../../components/ui/PageWrapper'
import { useNetworkMonitor } from '../../hooks/useNetworkMonitor'
import AgentStatus from '../../components/network-monitor/AgentStatus'
import {
  Activity,
  Layers,
  Network,
  BarChart3,
  Settings as SettingsIcon,
  Play,
  Square,
  RefreshCw,
  Clock,
  Wifi,
  ShieldCheck,
  ShieldAlert,
  AlertCircle,
} from 'lucide-react'
import { cn } from '../../lib/utils'
import type {
  NetworkSummary,
  NetworkInterface,
  TrafficDataPoint,
} from '../../types/networkMonitor'

export interface NetworkMonitorContextType {
  summary: NetworkSummary | null
  interfaces: NetworkInterface[]
  trafficHistory: TrafficDataPoint[]
  isLoading: boolean
  isStarting: boolean
  isStopping: boolean
  error: string | null
  lastUpdated: Date | null
  start: (interfaceName?: string, forceAdapter?: string) => Promise<void>
  stop: () => Promise<void>
  refresh: () => Promise<void>
  reloadInterfaces: () => Promise<void>
}

const TABS = [
  { to: '/network-monitor', label: 'Overview', icon: Activity, end: true },
  { to: '/network-monitor/connections', label: 'Connections', icon: Network },
  { to: '/network-monitor/protocols', label: 'Protocol Analyzer', icon: Layers },
  { to: '/network-monitor/alerts', label: 'Alerts', icon: ShieldAlert },
  { to: '/network-monitor/analytics', label: 'Analytics', icon: BarChart3 },
  { to: '/network-monitor/settings', label: 'Settings', icon: SettingsIcon },
]

export default function NetworkMonitorLayout() {
  const monitor = useNetworkMonitor()
  const location = useLocation()

  const {
    summary,
    interfaces,
    trafficHistory,
    isLoading,
    isStarting,
    isStopping,
    error,
    lastUpdated,
    start,
    stop,
    refresh,
    reloadInterfaces,
  } = monitor

  const agentState = summary?.status.state || 'STOPPED'
  const isRunning = agentState === 'RUNNING'
  const currentInterface = summary?.selected_interface || 'Auto'

  const formatLastUpdated = (d: Date | null) => {
    if (!d) return '-'
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
  }

  return (
    <PageWrapper>
      <div className="max-w-7xl mx-auto px-4 sm:px-6 pt-24 pb-20 space-y-6">
        {/* Shared Network Monitor Header */}
        <div className="glass-card rounded-2xl border border-cyber-border p-6 shadow-xl relative overflow-hidden">
          {/* Subtle accent glow */}
          <div className="absolute top-0 right-0 w-96 h-96 bg-[#0d6efd]/5 rounded-full blur-3xl pointer-events-none -mr-20 -mt-20" />

          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 relative z-10">
            {/* Title & Description */}
            <div className="space-y-1.5">
              <div className="flex items-center gap-3 flex-wrap">
                <div className="w-10 h-10 rounded-xl bg-[#0d6efd]/15 border border-[#0d6efd]/30 text-[#0d6efd] flex items-center justify-center shadow-[0_0_15px_rgba(13,110,253,0.2)]">
                  <Activity size={22} />
                </div>
                <h1 className="text-2xl sm:text-3xl font-extrabold text-gray-900 dark:text-white tracking-tight">
                  Network Monitor
                </h1>
                <AgentStatus state={agentState} />
              </div>
              <p className="text-sm text-gray-400 max-w-2xl leading-relaxed">
                Real-time network traffic monitoring and analysis for this machine. Zero-payload in-memory telemetry.
              </p>
            </div>

            {/* Quick Actions & Meta */}
            <div className="flex flex-wrap items-center gap-3">
              {/* Active Interface Badge */}
              <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-cyber-surface/70 border border-cyber-border/60 text-xs font-mono text-gray-300">
                <Wifi size={14} className="text-[#0d6efd]" />
                <span className="text-gray-400">Adapter:</span>
                <span className="font-bold text-gray-200">{currentInterface}</span>
              </div>

              {/* Last Updated Timestamp */}
              <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-cyber-surface/70 border border-cyber-border/60 text-xs font-mono text-gray-400">
                <Clock size={13} />
                <span>{formatLastUpdated(lastUpdated)}</span>
              </div>

              {/* Refresh Button */}
              <button
                onClick={() => refresh()}
                disabled={isLoading}
                className="p-2 rounded-xl bg-cyber-surface/70 hover:bg-cyber-surface border border-cyber-border/60 text-gray-400 hover:text-white transition-colors disabled:opacity-50"
                title="Refresh Metrics"
              >
                <RefreshCw size={15} className={cn(isLoading && 'animate-spin')} />
              </button>

              {/* Start / Stop Toggle Button */}
              {isRunning ? (
                <button
                  onClick={() => stop()}
                  disabled={isStopping}
                  className="flex items-center gap-2 px-4 py-2 rounded-xl bg-rose-500/20 hover:bg-rose-500/30 border border-rose-500/40 text-rose-300 text-xs font-mono font-bold transition-all shadow-[0_0_15px_rgba(244,63,94,0.15)] disabled:opacity-50"
                >
                  <Square size={13} className="fill-current" />
                  <span>{isStopping ? 'STOPPING...' : 'STOP MONITORING'}</span>
                </button>
              ) : (
                <button
                  onClick={() => start(currentInterface !== 'Auto' ? currentInterface : undefined)}
                  disabled={isStarting}
                  className="flex items-center gap-2 px-4 py-2 rounded-xl bg-[#0d6efd] hover:bg-[#0b5ed7] text-white text-xs font-mono font-bold transition-all shadow-[0_0_20px_rgba(13,110,253,0.3)] disabled:opacity-50"
                >
                  <Play size={13} className="fill-current" />
                  <span>{isStarting ? 'STARTING...' : 'START MONITORING'}</span>
                </button>
              )}
            </div>
          </div>

          {/* Error Banner if any */}
          {error && (
            <div className="mt-4 p-3 rounded-xl bg-red-500/10 border border-red-500/30 text-red-300 text-xs font-mono flex items-center gap-2">
              <AlertCircle size={15} className="flex-shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {/* Internal Tab Navigation */}
          <div className="mt-6 pt-4 border-t border-cyber-border/40 flex items-center gap-1 sm:gap-2 overflow-x-auto scrollbar-none">
            {TABS.map(({ to, label, icon: Icon, end }) => (
              <NavLink
                key={to}
                to={to}
                end={end}
                className={({ isActive }) =>
                  cn(
                    'flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs sm:text-sm font-medium transition-all whitespace-nowrap',
                    isActive
                      ? 'bg-[#0d6efd]/15 text-[#0d6efd] border border-[#0d6efd]/30 font-semibold shadow-sm'
                      : 'text-gray-400 hover:text-white hover:bg-white/5'
                  )
                }
              >
                <Icon size={16} />
                <span>{label}</span>
              </NavLink>
            ))}
          </div>
        </div>

        {/* Tab Route Content */}
        <Outlet
          context={{
            summary,
            interfaces,
            trafficHistory,
            isLoading,
            isStarting,
            isStopping,
            error,
            lastUpdated,
            start,
            stop,
            refresh,
            reloadInterfaces,
          } as NetworkMonitorContextType}
        />
      </div>
    </PageWrapper>
  )
}
