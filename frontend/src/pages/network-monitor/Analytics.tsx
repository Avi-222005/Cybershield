import React, { useEffect, useState } from 'react'
import { useOutletContext } from 'react-router-dom'
import type { NetworkMonitorContextType } from './NetworkMonitorLayout'
import type { AnalyticsData } from '../../types/networkMonitor'
import { getAnalytics } from '../../services/networkMonitorService'
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts'
import {
  BarChart3,
  HardDriveDownload,
  HardDriveUpload,
  Zap,
  Globe,
  Cpu,
  Activity,
  Info,
  Clock,
  RefreshCw,
  Layers,
} from 'lucide-react'

function formatBytes(bytes: number = 0): { value: string; unit: string } {
  if (bytes === 0) return { value: '0', unit: 'B' }
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(1024))
  const val = (bytes / Math.pow(1024, i)).toFixed(2)
  return { value: val, unit: units[i] || 'B' }
}

export default function Analytics() {
  const { summary } = useOutletContext<NetworkMonitorContextType>()
  const agentState = summary?.status.state || 'STOPPED'
  const isRunning = agentState === 'RUNNING'

  const [analytics, setAnalytics] = useState<AnalyticsData | null>(null)
  const [isLoading, setIsLoading] = useState(true)

  const fetchAnalyticsData = async () => {
    try {
      const res = await getAnalytics(15)
      if (res.success && res.analytics) {
        setAnalytics(res.analytics)
      }
    } catch (err: any) {
      console.warn('Failed to load analytics:', err?.message)
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    fetchAnalyticsData()
    const timer = setInterval(() => {
      if (document.visibilityState === 'visible' && isRunning) {
        fetchAnalyticsData()
      }
    }, 2500)
    return () => clearInterval(timer)
  }, [isRunning])

  const bw = analytics?.bandwidth
  const totalCombinedBytes = (bw?.total_bytes_sent || 0) + (bw?.total_bytes_received || 0)
  const totalCombinedFormatted = formatBytes(totalCombinedBytes)
  const totalSentFormatted = formatBytes(bw?.total_bytes_sent || 0)
  const totalRecvFormatted = formatBytes(bw?.total_bytes_received || 0)

  // Chart data formatted for hourly upload/download in MB
  const chartData = (analytics?.hourly_traffic || []).map((h) => ({
    label: h.label,
    downloadMB: Number(((h.download_bytes || 0) / (1024 * 1024)).toFixed(3)),
    uploadMB: Number(((h.upload_bytes || 0) / (1024 * 1024)).toFixed(3)),
    packets: h.packets,
  }))

  return (
    <div className="space-y-6">
      {/* Session Analytics Notice */}
      <div className="glass-card rounded-2xl border border-cyber-border p-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs font-mono">
        <div className="flex items-center gap-2.5 text-gray-300">
          <Info size={16} className="text-[#0d6efd] flex-shrink-0" />
          <span>
            Analytics are computed incrementally from the <strong>current in-memory session only</strong>. Zero database retention.
          </span>
        </div>
        <div className="flex items-center gap-2 text-gray-500">
          <span>Session uptime: {analytics?.session.uptime_seconds || 0}s</span>
          <button
            type="button"
            onClick={fetchAnalyticsData}
            className="p-1 rounded hover:bg-cyber-surface/60 text-gray-400 hover:text-white"
            title="Refresh analytics"
          >
            <RefreshCw size={13} className={isLoading ? 'animate-spin' : ''} />
          </button>
        </div>
      </div>

      {/* Primary Volume & Speed Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Data Combined */}
        <div className="glass-card rounded-xl p-5 border border-cyber-border flex flex-col justify-between">
          <span className="text-xs text-gray-400 font-mono">Total Cumulative Volume</span>
          <div className="flex items-baseline gap-2 my-2">
            <span className="text-3xl font-bold font-mono text-gray-900 dark:text-white">
              {totalCombinedFormatted.value}
            </span>
            <span className="text-sm font-mono text-gray-400">{totalCombinedFormatted.unit}</span>
          </div>
          <div className="flex items-center justify-between text-[11px] text-gray-500 font-mono">
            <span>Up: {totalSentFormatted.value} {totalSentFormatted.unit}</span>
            <span>Down: {totalRecvFormatted.value} {totalRecvFormatted.unit}</span>
          </div>
        </div>

        {/* Peak Download Speed */}
        <div className="glass-card rounded-xl p-5 border border-cyber-border flex flex-col justify-between">
          <span className="text-xs text-emerald-400 font-mono flex items-center gap-1.5">
            <Zap size={14} /> Peak Download Speed
          </span>
          <div className="flex items-baseline gap-2 my-2">
            <span className="text-3xl font-bold font-mono text-emerald-400">
              {bw?.peak_download_mbps ? bw.peak_download_mbps.toFixed(2) : '0.00'}
            </span>
            <span className="text-sm font-mono text-gray-400">Mbps</span>
          </div>
          <span className="text-[11px] text-gray-500 font-mono">
            Avg:{' '}
            {bw?.has_sufficient_samples
              ? `${bw.average_download_mbps.toFixed(2)} Mbps`
              : 'Collecting samples...'}
          </span>
        </div>

        {/* Peak Upload Speed */}
        <div className="glass-card rounded-xl p-5 border border-cyber-border flex flex-col justify-between">
          <span className="text-xs text-[#0d6efd] font-mono flex items-center gap-1.5">
            <Zap size={14} /> Peak Upload Speed
          </span>
          <div className="flex items-baseline gap-2 my-2">
            <span className="text-3xl font-bold font-mono text-[#0d6efd]">
              {bw?.peak_upload_mbps ? bw.peak_upload_mbps.toFixed(2) : '0.00'}
            </span>
            <span className="text-sm font-mono text-gray-400">Mbps</span>
          </div>
          <span className="text-[11px] text-gray-500 font-mono">
            Avg:{' '}
            {bw?.has_sufficient_samples
              ? `${bw.average_upload_mbps.toFixed(2)} Mbps`
              : 'Collecting samples...'}
          </span>
        </div>

        {/* Total Packets Captured */}
        <div className="glass-card rounded-xl p-5 border border-cyber-border flex flex-col justify-between">
          <span className="text-xs text-purple-400 font-mono flex items-center gap-1.5">
            <Activity size={14} /> Captured Packets
          </span>
          <div className="flex items-baseline gap-2 my-2">
            <span className="text-3xl font-bold font-mono text-gray-200">
              {(analytics?.packets.total_captured || 0).toLocaleString()}
            </span>
            <span className="text-sm font-mono text-gray-400">frames</span>
          </div>
          <span className="text-[11px] text-gray-500 font-mono">
            Rate: {(analytics?.packets.current_packets_per_sec || 0).toFixed(1)} pkts/s (Avg:{' '}
            {(analytics?.packets.average_packets_per_sec || 0).toFixed(1)})
          </span>
        </div>
      </div>

      {/* Hourly Upload vs Download Volume Comparison Chart */}
      <div className="glass-card rounded-2xl border border-cyber-border p-6 shadow-xl">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-5 border-b border-cyber-border/40 pb-4">
          <div>
            <h3 className="text-base font-bold text-gray-900 dark:text-white flex items-center gap-2">
              <BarChart3 size={18} className="text-[#0d6efd]" />
              Session Traffic Distribution (Upload vs Download)
            </h3>
            <p className="text-xs text-gray-400 mt-0.5">
              Hourly bounded time-buckets tracking data transfer volume in megabytes (MB)
            </p>
          </div>
          <span className="text-xs font-mono text-gray-400 bg-cyber-surface/60 px-2.5 py-1 rounded-lg border border-cyber-border/40">
            {chartData.length} Time Bucket{chartData.length !== 1 ? 's' : ''}
          </span>
        </div>

        {chartData.length === 0 ? (
          <div className="h-56 flex items-center justify-center text-xs font-mono text-gray-500">
            No session traffic recorded yet. Start monitoring to collect hourly buckets.
          </div>
        ) : (
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" vertical={false} />
                <XAxis dataKey="label" stroke="#9ca3af" fontSize={11} fontFamily="monospace" />
                <YAxis stroke="#9ca3af" fontSize={11} fontFamily="monospace" unit=" MB" />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0a0f1d',
                    borderColor: '#1f2937',
                    borderRadius: '0.75rem',
                    fontSize: '11px',
                    fontFamily: 'monospace',
                  }}
                  itemStyle={{ color: '#e5e7eb' }}
                />
                <Legend wrapperStyle={{ fontSize: '11px', fontFamily: 'monospace' }} />
                <Bar dataKey="downloadMB" name="Download (MB)" fill="#10b981" radius={[4, 4, 0, 0]} />
                <Bar dataKey="uploadMB" name="Upload (MB)" fill="#0d6efd" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>

      {/* Top Communicating Endpoints Table */}
      <div className="glass-card rounded-2xl border border-cyber-border overflow-hidden">
        <div className="p-4 sm:p-5 border-b border-cyber-border/40 flex items-center justify-between">
          <div>
            <h3 className="text-base font-bold text-gray-900 dark:text-white flex items-center gap-2">
              <Globe size={18} className="text-[#0d6efd]" />
              Top Communicating IP Endpoints
            </h3>
            <p className="text-xs text-gray-400 mt-0.5">
              Incremental session IP tracking with packet, byte, and directional breakdowns
            </p>
          </div>
          <span className="text-xs font-mono text-gray-400 bg-cyber-surface/60 px-2.5 py-1 rounded-lg border border-cyber-border/40">
            Total Tracked: {analytics?.total_tracked_ips_count || 0}
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs font-mono">
            <thead>
              <tr className="border-b border-cyber-border/40 bg-cyber-surface/40 text-gray-400 font-medium select-none">
                <th className="py-3 px-4">RANK</th>
                <th className="py-3 px-4">IP ADDRESS</th>
                <th className="py-3 px-4">OBSERVED PACKETS</th>
                <th className="py-3 px-4">ESTIMATED VOLUME</th>
                <th className="py-3 px-4">DIRECTION BREAKDOWN</th>
                <th className="py-3 px-4 text-right">ACTIVITY SHARE</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-cyber-border/20">
              {(!analytics?.top_ips || analytics.top_ips.length === 0) ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-gray-500">
                    No endpoint traffic recorded in current session
                  </td>
                </tr>
              ) : (
                analytics.top_ips.map((item, idx) => {
                  const maxPkts = analytics.top_ips[0]?.packets || 1
                  const sharePct = (item.packets / maxPkts) * 100
                  const bytesFormatted = formatBytes(item.bytes)

                  return (
                    <tr key={item.ip} className="hover:bg-cyber-surface/60 transition-colors">
                      <td className="py-3 px-4 text-gray-500">#{idx + 1}</td>
                      <td className="py-3 px-4 font-bold text-gray-200">{item.ip}</td>
                      <td className="py-3 px-4 text-gray-300 font-bold">{item.packets} pkts</td>
                      <td className="py-3 px-4 text-gray-400 font-mono">
                        {bytesFormatted.value} {bytesFormatted.unit}
                      </td>
                      <td className="py-3 px-4 text-gray-400">
                        <span className="text-emerald-400">In: {item.inbound_count}</span>
                        <span className="mx-1 text-gray-600">/</span>
                        <span className="text-[#0d6efd]">Out: {item.outbound_count}</span>
                      </td>
                      <td className="py-3 px-4 text-right w-1/4">
                        <div className="w-full bg-cyber-surface/80 rounded-full h-2 overflow-hidden border border-cyber-border/40">
                          <div
                            className="bg-[#0d6efd] h-full rounded-full transition-all duration-300"
                            style={{ width: `${Math.min(100, Math.max(5, sharePct))}%` }}
                          />
                        </div>
                      </td>
                    </tr>
                  )
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Best-Effort Socket-Correlated Process Attribution Table */}
      <div className="glass-card rounded-2xl border border-cyber-border overflow-hidden">
        <div className="p-4 sm:p-5 border-b border-cyber-border/40 flex items-center justify-between">
          <div>
            <h3 className="text-base font-bold text-gray-900 dark:text-white flex items-center gap-2">
              <Cpu size={18} className="text-[#0d6efd]" />
              Socket-Correlated Process Attribution
            </h3>
            <p className="text-xs text-gray-400 mt-0.5">
              Correlated from active socket endpoints. Best-effort attribution without invasive kernel hooks.
            </p>
          </div>
          <span className="text-xs font-mono text-gray-400 bg-cyber-surface/60 px-2.5 py-1 rounded-lg border border-cyber-border/40">
            {analytics?.processes?.length || 0} Processes
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs font-mono">
            <thead>
              <tr className="border-b border-cyber-border/40 bg-cyber-surface/40 text-gray-400 font-medium select-none">
                <th className="py-3 px-4">PROCESS</th>
                <th className="py-3 px-4">PID</th>
                <th className="py-3 px-4">OPEN SOCKETS</th>
                <th className="py-3 px-4">PROTOCOLS</th>
                <th className="py-3 px-4">REMOTE ENDPOINTS SAMPLE</th>
                <th className="py-3 px-4 text-right">ATTRIBUTION TYPE</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-cyber-border/20">
              {(!analytics?.processes || analytics.processes.length === 0) ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-gray-500">
                    No socket connections available for process attribution
                  </td>
                </tr>
              ) : (
                analytics.processes.map((proc, idx) => (
                  <tr key={`${proc.process_name}-${proc.pid || idx}`} className="hover:bg-cyber-surface/60 transition-colors">
                    <td className="py-3 px-4 font-bold text-gray-200">{proc.process_name}</td>
                    <td className="py-3 px-4 text-gray-400">{proc.pid ? proc.pid : '-'}</td>
                    <td className="py-3 px-4 text-[#0d6efd] font-bold">{proc.socket_count}</td>
                    <td className="py-3 px-4 text-gray-300 uppercase">{proc.protocols.join(', ')}</td>
                    <td className="py-3 px-4 text-gray-400 truncate max-w-xs">
                      {proc.remote_endpoints_sample.length > 0
                        ? proc.remote_endpoints_sample.join(', ')
                        : 'Local / Listening'}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <span className="inline-flex items-center px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20 text-[10px]">
                        Socket Correlated
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
