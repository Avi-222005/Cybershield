import React, { useMemo } from 'react'
import { useOutletContext } from 'react-router-dom'
import type { NetworkMonitorContextType } from './NetworkMonitorLayout'
import ProtocolChart from '../../components/network-monitor/ProtocolChart'
import { Layers, ArrowDownLeft, ArrowUpRight, Repeat, HelpCircle, Shield, Info } from 'lucide-react'

export default function Protocols() {
  const { summary } = useOutletContext<NetworkMonitorContextType>()
  const protocols = summary?.protocols

  const { tableRows, totalPackets, directionStats } = useMemo(() => {
    const dist = protocols?.protocol_distribution || {}
    const total = protocols?.total_packets_captured || 0

    const rows = Object.entries(dist).map(([proto, count]) => {
      const pct = total > 0 ? (count / total) * 100 : 0
      return {
        protocol: proto.toUpperCase().trim(),
        count,
        percentage: pct,
      }
    })

    rows.sort((a, b) => b.count - a.count)

    const dirs = protocols?.direction_distribution || {
      inbound: 0,
      outbound: 0,
      internal: 0,
      unknown: 0,
    }

    return {
      tableRows: rows,
      totalPackets: total,
      directionStats: dirs,
    }
  }, [protocols])

  const dirTotal =
    (directionStats.inbound || 0) +
    (directionStats.outbound || 0) +
    (directionStats.internal || 0) +
    (directionStats.unknown || 0)

  const calcDirPct = (val: number) => (dirTotal > 0 ? ((val / dirTotal) * 100).toFixed(1) : '0')

  return (
    <div className="space-y-6">
      {/* Top Protocol Analysis Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Donut Chart & Direction (2 cols) */}
        <div className="lg:col-span-2">
          <ProtocolChart protocols={protocols} />
        </div>

        {/* Informational Scope Card (1 col) */}
        <div className="lg:col-span-1 glass-card rounded-2xl border border-cyber-border p-5 flex flex-col justify-between">
          <div>
            <h3 className="text-base font-bold text-gray-900 dark:text-white flex items-center gap-2 mb-2">
              <Info size={18} className="text-[#0d6efd]" />
              Telemetry Scope
            </h3>
            <p className="text-xs text-gray-400 mb-4 leading-relaxed font-mono">
              Metrics reflect cumulative packets observed by the capture engine in the current monitoring session.
            </p>

            <div className="space-y-2.5 text-xs font-mono">
              <div className="p-3 rounded-xl bg-cyber-surface/60 border border-cyber-border/40 space-y-1">
                <span className="text-gray-400 block text-[11px]">Total Observed Frames:</span>
                <span className="text-xl font-bold text-white">{totalPackets.toLocaleString()}</span>
              </div>

              <div className="p-3 rounded-xl bg-cyber-surface/60 border border-cyber-border/40 space-y-1">
                <span className="text-gray-400 block text-[11px]">Capture Packet Rate:</span>
                <span className="text-xl font-bold text-emerald-400">
                  {(protocols?.packets_per_sec || 0).toFixed(1)} pkts/s
                </span>
              </div>

              <div className="p-3 rounded-xl bg-cyber-surface/60 border border-cyber-border/40 space-y-1">
                <span className="text-gray-400 block text-[11px]">Dropped / Saturated Packets:</span>
                <span className="text-xl font-bold text-gray-300">
                  {protocols?.dropped_packets || 0}
                </span>
              </div>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-cyber-border/40 text-[11px] text-gray-500 font-mono">
            Zero payload storage policy active. Metadata is purged on shutdown.
          </div>
        </div>
      </div>

      {/* Protocol Summary Table */}
      <div className="glass-card rounded-2xl border border-cyber-border overflow-hidden">
        <div className="p-4 sm:p-5 border-b border-cyber-border/40 flex items-center justify-between">
          <div>
            <h3 className="text-base font-bold text-gray-900 dark:text-white flex items-center gap-2">
              <Layers size={18} className="text-[#0d6efd]" />
              Protocol Breakdown & Volume
            </h3>
            <p className="text-xs text-gray-400 mt-0.5">
              Cumulative frame count and calculated percentage share across all observed protocols
            </p>
          </div>
          <span className="text-xs font-mono text-gray-400 bg-cyber-surface/60 px-2.5 py-1 rounded-lg border border-cyber-border/40">
            {tableRows.length} protocols detected
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs font-mono">
            <thead>
              <tr className="border-b border-cyber-border/40 bg-cyber-surface/40 text-gray-400 font-medium select-none">
                <th className="py-3 px-4">PROTOCOL</th>
                <th className="py-3 px-4">PACKET COUNT</th>
                <th className="py-3 px-4">SHARE</th>
                <th className="py-3 px-4 text-right">RELATIVE DISTRIBUTION</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-cyber-border/20">
              {tableRows.length === 0 ? (
                <tr>
                  <td colSpan={4} className="py-12 text-center text-gray-500">
                    No protocol traffic captured in current session
                  </td>
                </tr>
              ) : (
                tableRows.map((row) => (
                  <tr key={row.protocol} className="hover:bg-cyber-surface/60 transition-colors">
                    <td className="py-3 px-4 font-bold text-gray-200">
                      <span className="px-2 py-0.5 rounded text-[11px] bg-[#0d6efd]/10 text-[#0d6efd] border border-[#0d6efd]/30">
                        {row.protocol}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-gray-300 font-bold">
                      {row.count.toLocaleString()}
                    </td>
                    <td className="py-3 px-4 text-gray-400">
                      {row.percentage.toFixed(2)}%
                    </td>
                    <td className="py-3 px-4 text-right w-1/3">
                      <div className="w-full bg-cyber-surface/80 rounded-full h-2 overflow-hidden border border-cyber-border/40">
                        <div
                          className="bg-[#0d6efd] h-full rounded-full transition-all duration-300"
                          style={{ width: `${Math.min(100, Math.max(1, row.percentage))}%` }}
                        />
                      </div>
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
