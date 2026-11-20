import React, { useEffect, useState } from 'react'
import { useOutletContext } from 'react-router-dom'
import type { NetworkMonitorContextType } from './NetworkMonitorLayout'
import ConnectionTable from '../../components/network-monitor/ConnectionTable'
import { getNetworkConnections } from '../../services/networkMonitorService'
import type { NetworkConnection } from '../../types/networkMonitor'
import { Network, Server, RefreshCw, Radio, ShieldCheck } from 'lucide-react'

export default function Connections() {
  const { summary } = useOutletContext<NetworkMonitorContextType>()
  const [connections, setConnections] = useState<NetworkConnection[]>([])
  const [isLoading, setIsLoading] = useState<boolean>(true)
  const [error, setError] = useState<string | null>(null)

  const isRunning = summary?.status.state === 'RUNNING'

  const fetchConnections = async () => {
    setIsLoading(true)
    setError(null)
    try {
      const res = await getNetworkConnections()
      if (res.success) {
        setConnections(res.connections)
      }
    } catch (err: any) {
      setError(err?.message || 'Failed to retrieve connection snapshot')
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    fetchConnections()
    // Poll connections every 3 seconds if agent is running
    const interval = isRunning ? 3000 : 8000
    const timer = setInterval(() => {
      if (document.visibilityState === 'visible') {
        fetchConnections()
      }
    }, interval)

    return () => clearInterval(timer)
  }, [isRunning])

  // Count summaries
  const establishedCount = connections.filter((c) => c.status === 'ESTABLISHED').length
  const listenCount = connections.filter((c) => c.status === 'LISTEN').length
  const tcpCount = connections.filter((c) => c.protocol.toLowerCase() === 'tcp').length
  const udpCount = connections.filter((c) => c.protocol.toLowerCase() === 'udp').length

  return (
    <div className="space-y-6">
      {/* Metrics Banner */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 sm:gap-4 font-mono text-xs">
        <div className="glass-card rounded-xl p-4 border border-cyber-border">
          <span className="text-gray-400 block mb-1">Total Internet Sockets</span>
          <span className="text-2xl font-bold text-gray-900 dark:text-white">
            {connections.length}
          </span>
          <span className="text-[11px] text-gray-500 block mt-1">Active OS endpoints</span>
        </div>

        <div className="glass-card rounded-xl p-4 border border-cyber-border">
          <span className="text-emerald-400 block mb-1">ESTABLISHED</span>
          <span className="text-2xl font-bold text-emerald-400">{establishedCount}</span>
          <span className="text-[11px] text-gray-500 block mt-1">Live peer channels</span>
        </div>

        <div className="glass-card rounded-xl p-4 border border-cyber-border">
          <span className="text-[#0d6efd] block mb-1">LISTEN Sockets</span>
          <span className="text-2xl font-bold text-[#0d6efd]">{listenCount}</span>
          <span className="text-[11px] text-gray-500 block mt-1">Awaiting connections</span>
        </div>

        <div className="glass-card rounded-xl p-4 border border-cyber-border">
          <span className="text-purple-400 block mb-1">Protocols (TCP / UDP)</span>
          <span className="text-2xl font-bold text-gray-200">
            {tcpCount} / {udpCount}
          </span>
          <span className="text-[11px] text-gray-500 block mt-1">Stream vs Datagram</span>
        </div>
      </div>

      {/* Main Connection Table */}
      <ConnectionTable
        connections={connections}
        isLoading={isLoading}
        error={error}
        onRefresh={fetchConnections}
      />
    </div>
  )
}
