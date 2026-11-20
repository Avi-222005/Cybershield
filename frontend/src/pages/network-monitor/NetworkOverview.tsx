import React from 'react'
import { useOutletContext } from 'react-router-dom'
import type { NetworkMonitorContextType } from './NetworkMonitorLayout'
import NetworkStatCard from '../../components/network-monitor/NetworkStatCard'
import TrafficChart from '../../components/network-monitor/TrafficChart'
import ProtocolChart from '../../components/network-monitor/ProtocolChart'
import RecentActivity from '../../components/network-monitor/RecentActivity'
import NetworkEmptyState from '../../components/network-monitor/NetworkEmptyState'
import {
  ArrowDownCircle,
  ArrowUpCircle,
  Network,
  Activity,
  HardDriveDownload,
  HardDriveUpload,
  Wifi,
  Shield,
  CheckCircle2,
  AlertTriangle,
} from 'lucide-react'

function formatBytes(bytes: number = 0): { value: string; unit: string } {
  if (bytes === 0) return { value: '0', unit: 'B' }
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(1024))
  const val = (bytes / Math.pow(1024, i)).toFixed(2)
  return { value: val, unit: units[i] || 'B' }
}

export default function NetworkOverview() {
  const { summary, trafficHistory, start, isStarting } = useOutletContext<NetworkMonitorContextType>()

  const isRunning = summary?.status.state === 'RUNNING'
  const traffic = summary?.traffic
  const protocols = summary?.protocols
  const connCount = summary?.active_connections_count || 0
  const recentEvents = summary?.recent_events || []
  const currentIface = summary?.selected_interface || 'N/A'

  const downBytesFormatted = formatBytes(traffic?.total_bytes_received || 0)
  const upBytesFormatted = formatBytes(traffic?.total_bytes_sent || 0)

  const downKbps = traffic?.download_bytes_per_sec ? (traffic.download_bytes_per_sec / 1024).toFixed(1) : '0.0'
  const upKbps = traffic?.upload_bytes_per_sec ? (traffic.upload_bytes_per_sec / 1024).toFixed(1) : '0.0'

  return (
    <div className="space-y-6">
      {/* 6 High-Level Statistics Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3 sm:gap-4">
        {/* 1. Download Speed */}
        <NetworkStatCard
          label="Download Speed"
          value={(traffic?.download_mbps || 0).toFixed(2)}
          unit="Mbps"
          secondary={`${downKbps} KB/s`}
          icon={ArrowDownCircle}
          iconColor="text-emerald-400"
        />

        {/* 2. Upload Speed */}
        <NetworkStatCard
          label="Upload Speed"
          value={(traffic?.upload_mbps || 0).toFixed(2)}
          unit="Mbps"
          secondary={`${upKbps} KB/s`}
          icon={ArrowUpCircle}
          iconColor="text-[#0d6efd]"
        />

        {/* 3. Active Connections */}
        <NetworkStatCard
          label="Active Sockets"
          value={connCount}
          unit="sockets"
          secondary="TCP & UDP in-memory"
          icon={Network}
          iconColor="text-cyan-400"
        />

        {/* 4. Packets Per Second */}
        <NetworkStatCard
          label="Packet Rate"
          value={(protocols?.packets_per_sec || 0).toFixed(1)}
          unit="pkts/s"
          secondary={`${(protocols?.total_packets_captured || 0).toLocaleString()} captured`}
          icon={Activity}
          iconColor="text-amber-400"
        />

        {/* 5. Total Data Received */}
        <NetworkStatCard
          label="Total Received"
          value={downBytesFormatted.value}
          unit={downBytesFormatted.unit}
          secondary={`${(traffic?.packets_recv_per_sec || 0).toFixed(0)} pkts/s`}
          icon={HardDriveDownload}
          iconColor="text-purple-400"
        />

        {/* 6. Total Data Sent */}
        <NetworkStatCard
          label="Total Sent"
          value={upBytesFormatted.value}
          unit={upBytesFormatted.unit}
          secondary={`${(traffic?.packets_sent_per_sec || 0).toFixed(0)} pkts/s`}
          icon={HardDriveUpload}
          iconColor="text-blue-400"
        />
      </div>

      {/* Stopped Banner Notification if not active */}
      {!isRunning && (
        <NetworkEmptyState
          title="Monitoring Agent is Idle"
          description="Start the autonomous network monitoring daemon to capture live transmission throughput, sockets, and metadata on this machine."
          actionLabel="Start Monitoring Now"
          onAction={() => start(currentIface !== 'Auto' ? currentIface : undefined)}
          isActionLoading={isStarting}
        />
      )}

      {/* Main Real-Time Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Live Bandwidth Chart (2 cols) */}
        <div className="lg:col-span-2">
          <TrafficChart
            data={trafficHistory}
            isMonitoring={isRunning}
            currentDownloadMbps={traffic?.download_mbps || 0}
            currentUploadMbps={traffic?.upload_mbps || 0}
          />
        </div>

        {/* Protocol Distribution Donut (1 col) */}
        <div className="lg:col-span-1">
          <ProtocolChart protocols={protocols} />
        </div>
      </div>

      {/* Interface Summary & Recent Activity Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Interface Info Card (1 col) */}
        <div className="lg:col-span-1 glass-card rounded-2xl border border-cyber-border p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-base font-bold text-gray-900 dark:text-white flex items-center gap-2">
                <Wifi size={18} className="text-[#0d6efd]" />
                Selected Adapter
              </h3>
              <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                ACTIVE
              </span>
            </div>

            <div className="space-y-3 font-mono text-xs">
              <div className="p-3 rounded-xl bg-cyber-surface/60 border border-cyber-border/40 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">Adapter Name:</span>
                  <span className="font-bold text-gray-200">{currentIface}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">Capture Engine:</span>
                  <span className="text-emerald-400 font-semibold">
                    {summary?.status.components?.packet_capture?.details || 'Online'}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">In-Memory Events:</span>
                  <span className="text-gray-200 font-bold">
                    {summary?.status.memory_buffer_usage?.packet_events || 0} / 5000
                  </span>
                </div>
              </div>

              <div className="p-3 rounded-xl bg-cyber-surface/60 border border-cyber-border/40 space-y-1.5 text-[11px] text-gray-400">
                <div className="flex items-center gap-1.5 text-gray-300 font-semibold">
                  <Shield size={13} className="text-cyan-400" />
                  Privacy & Data Security Policy
                </div>
                <p className="leading-relaxed">
                  Traffic is processed strictly in-memory. Payloads are never captured, retained, or logged to disk.
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Recent Traffic Metadata Stream (2 cols) */}
        <div className="lg:col-span-2">
          <RecentActivity events={recentEvents} />
        </div>
      </div>
    </div>
  )
}
