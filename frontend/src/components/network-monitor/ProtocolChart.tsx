import React, { useMemo } from 'react'
import { ResponsiveContainer, PieChart, Pie, Cell, Tooltip } from 'recharts'
import type { PacketCaptureStats } from '../../types/networkMonitor'
import { Layers, ArrowDownLeft, ArrowUpRight, Repeat, HelpCircle } from 'lucide-react'

interface ProtocolChartProps {
  protocols?: PacketCaptureStats
}

const PROTOCOL_COLORS: Record<string, string> = {
  TCP: '#0d6efd',
  UDP: '#8b5cf6',
  TLS: '#10b981',
  'TLS/HTTPS': '#10b981',
  HTTPS: '#10b981',
  DNS: '#f59e0b',
  HTTP: '#06b6d4',
  ARP: '#64748b',
  ICMP: '#ec4899',
  UNKNOWN: '#475569',
  OTHER: '#94a3b8',
}

export function ProtocolChart({ protocols }: ProtocolChartProps) {
  const { chartData, totalPackets, directionStats } = useMemo(() => {
    const dist = protocols?.protocol_distribution || {}
    const total = protocols?.total_packets_captured || 0

    const entries = Object.entries(dist).map(([proto, count]) => {
      const normalizedProto = proto.toUpperCase().trim()
      return {
        name: normalizedProto,
        value: count,
        color: PROTOCOL_COLORS[normalizedProto] || '#38bdf8',
      }
    })

    // Sort descending
    entries.sort((a, b) => b.value - a.value)

    const dirs = protocols?.direction_distribution || {
      inbound: 0,
      outbound: 0,
      internal: 0,
      unknown: 0,
    }

    return {
      chartData: entries,
      totalPackets: total,
      directionStats: dirs,
    }
  }, [protocols])

  const CustomTooltip = ({ active, payload }: any) => {
    if (active && payload && payload.length) {
      const item = payload[0]
      const pct = totalPackets > 0 ? ((item.value / totalPackets) * 100).toFixed(1) : '0'
      return (
        <div className="glass-card rounded-xl p-2.5 border border-cyber-border text-xs font-mono shadow-xl">
          <div className="flex items-center gap-2 mb-1">
            <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: item.payload.color }} />
            <span className="font-bold text-gray-900 dark:text-white">{item.name}</span>
          </div>
          <div className="text-gray-400">
            Packets: <span className="text-gray-200 font-bold">{item.value.toLocaleString()}</span> ({pct}%)
          </div>
        </div>
      )
    }
    return null
  }

  const dirTotal =
    (directionStats.inbound || 0) +
    (directionStats.outbound || 0) +
    (directionStats.internal || 0) +
    (directionStats.unknown || 0)

  const calcDirPct = (val: number) => (dirTotal > 0 ? ((val / dirTotal) * 100).toFixed(1) : '0')

  return (
    <div className="glass-card rounded-2xl border border-cyber-border p-5 flex flex-col justify-between">
      <div className="mb-3">
        <h3 className="text-base font-bold text-gray-900 dark:text-white flex items-center gap-2">
          <Layers size={18} className="text-[#0d6efd]" />
          Protocol & Traffic Analysis
        </h3>
        <p className="text-xs text-gray-400 mt-0.5">
          Distribution of captured frame headers and transport protocols
        </p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 items-center">
        {/* Donut Chart */}
        <div className="h-48 sm:h-56 relative flex items-center justify-center">
          {chartData.length === 0 ? (
            <div className="text-xs text-gray-400 text-center">
              No protocol telemetry captured yet
            </div>
          ) : (
            <>
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Tooltip content={<CustomTooltip />} />
                  <Pie
                    data={chartData}
                    innerRadius={50}
                    outerRadius={75}
                    paddingAngle={3}
                    dataKey="value"
                  >
                    {chartData.map((entry, idx) => (
                      <Cell key={`cell-${idx}`} fill={entry.color} stroke="transparent" />
                    ))}
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
              <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                <span className="text-lg font-bold font-mono text-gray-900 dark:text-white">
                  {totalPackets.toLocaleString()}
                </span>
                <span className="text-[10px] text-gray-400 tracking-wider uppercase font-mono">
                  Packets
                </span>
              </div>
            </>
          )}
        </div>

        {/* Protocol Legend list */}
        <div className="space-y-2">
          <div className="text-[11px] font-mono text-gray-400 uppercase tracking-wider mb-2">
            Top Protocols
          </div>
          {chartData.length === 0 ? (
            <p className="text-xs text-gray-500">Awaiting capture stream...</p>
          ) : (
            <div className="space-y-1.5 max-h-40 overflow-y-auto pr-1">
              {chartData.slice(0, 5).map((item) => {
                const pct = totalPackets > 0 ? ((item.value / totalPackets) * 100).toFixed(1) : '0'
                return (
                  <div key={item.name} className="flex items-center justify-between text-xs font-mono">
                    <span className="flex items-center gap-2 text-gray-300">
                      <span className="w-2 h-2 rounded-full" style={{ backgroundColor: item.color }} />
                      {item.name}
                    </span>
                    <span className="text-gray-400">
                      <strong className="text-gray-200">{item.value.toLocaleString()}</strong> ({pct}%)
                    </span>
                  </div>
                )
              })}
            </div>
          )}
        </div>
      </div>

      {/* Traffic Direction Section */}
      <div className="mt-4 pt-4 border-t border-cyber-border/40">
        <div className="text-[11px] font-mono text-gray-400 uppercase tracking-wider mb-2 flex items-center justify-between">
          <span>Direction Distribution</span>
          <span>{dirTotal.toLocaleString()} total</span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs font-mono">
          <div className="p-2 rounded-lg bg-cyber-surface/60 border border-cyber-border/40">
            <div className="flex items-center gap-1.5 text-emerald-400 text-[11px] mb-1">
              <ArrowDownLeft size={13} />
              <span>Inbound</span>
            </div>
            <div className="text-sm font-bold text-gray-200">
              {directionStats.inbound.toLocaleString()}
            </div>
            <div className="text-[10px] text-gray-400">{calcDirPct(directionStats.inbound)}%</div>
          </div>

          <div className="p-2 rounded-lg bg-cyber-surface/60 border border-cyber-border/40">
            <div className="flex items-center gap-1.5 text-[#0d6efd] text-[11px] mb-1">
              <ArrowUpRight size={13} />
              <span>Outbound</span>
            </div>
            <div className="text-sm font-bold text-gray-200">
              {directionStats.outbound.toLocaleString()}
            </div>
            <div className="text-[10px] text-gray-400">{calcDirPct(directionStats.outbound)}%</div>
          </div>

          <div className="p-2 rounded-lg bg-cyber-surface/60 border border-cyber-border/40">
            <div className="flex items-center gap-1.5 text-purple-400 text-[11px] mb-1">
              <Repeat size={13} />
              <span>Internal</span>
            </div>
            <div className="text-sm font-bold text-gray-200">
              {directionStats.internal.toLocaleString()}
            </div>
            <div className="text-[10px] text-gray-400">{calcDirPct(directionStats.internal)}%</div>
          </div>

          <div className="p-2 rounded-lg bg-cyber-surface/60 border border-cyber-border/40">
            <div className="flex items-center gap-1.5 text-gray-400 text-[11px] mb-1">
              <HelpCircle size={13} />
              <span>Unknown</span>
            </div>
            <div className="text-sm font-bold text-gray-200">
              {directionStats.unknown.toLocaleString()}
            </div>
            <div className="text-[10px] text-gray-400">{calcDirPct(directionStats.unknown)}%</div>
          </div>
        </div>
      </div>
    </div>
  )
}
export default ProtocolChart
