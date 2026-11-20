import React, { useMemo } from 'react'
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  Legend,
  CartesianGrid,
} from 'recharts'
import type { TrafficDataPoint } from '../../types/networkMonitor'
import { ArrowDownCircle, ArrowUpCircle } from 'lucide-react'

interface TrafficChartProps {
  data: TrafficDataPoint[]
  isMonitoring: boolean
  currentDownloadMbps?: number
  currentUploadMbps?: number
}

export function TrafficChart({
  data,
  isMonitoring,
  currentDownloadMbps = 0,
  currentUploadMbps = 0,
}: TrafficChartProps) {
  // Compute max values for Y-axis domain
  const { maxVal, peakDown, peakUp } = useMemo(() => {
    let peakD = 0
    let peakU = 0
    data.forEach((d) => {
      if (d.downloadMbps > peakD) peakD = d.downloadMbps
      if (d.uploadMbps > peakU) peakU = d.uploadMbps
    })
    const highest = Math.max(peakD, peakU, 0.1)
    // Add 15% headroom
    return {
      maxVal: Number((highest * 1.15).toFixed(3)),
      peakDown: peakD,
      peakUp: peakU,
    }
  }, [data])

  const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      const down = payload.find((p: any) => p.dataKey === 'downloadMbps')?.value || 0
      const up = payload.find((p: any) => p.dataKey === 'uploadMbps')?.value || 0
      return (
        <div className="glass-card rounded-xl p-3 border border-cyber-border shadow-2xl text-xs space-y-1.5 font-mono">
          <div className="text-gray-400 font-sans font-medium border-b border-cyber-border/40 pb-1 mb-1">
            Time: {label}
          </div>
          <div className="flex items-center justify-between gap-4 text-emerald-400">
            <span className="flex items-center gap-1.5 font-sans">
              <span className="w-2 h-2 rounded-full bg-emerald-400" />
              Download:
            </span>
            <span className="font-bold">{down.toFixed(3)} Mbps</span>
          </div>
          <div className="flex items-center justify-between gap-4 text-[#0d6efd]">
            <span className="flex items-center gap-1.5 font-sans">
              <span className="w-2 h-2 rounded-full bg-[#0d6efd]" />
              Upload:
            </span>
            <span className="font-bold">{up.toFixed(3)} Mbps</span>
          </div>
        </div>
      )
    }
    return null
  }

  return (
    <div className="glass-card rounded-2xl border border-cyber-border p-5 flex flex-col justify-between">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
        <div>
          <h3 className="text-base font-bold text-gray-900 dark:text-white flex items-center gap-2">
            Real-Time Bandwidth
            {isMonitoring && (
              <span className="inline-block w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            )}
          </h3>
          <p className="text-xs text-gray-400 mt-0.5">
            Transmission throughput measured via operating system network interface counters
          </p>
        </div>

        <div className="flex items-center gap-4 text-xs font-mono">
          <div className="flex items-center gap-1.5 text-emerald-400">
            <ArrowDownCircle size={14} />
            <span>Down: <strong>{currentDownloadMbps.toFixed(2)} Mbps</strong></span>
          </div>
          <div className="flex items-center gap-1.5 text-[#0d6efd]">
            <ArrowUpCircle size={14} />
            <span>Up: <strong>{currentUploadMbps.toFixed(2)} Mbps</strong></span>
          </div>
        </div>
      </div>

      <div className="w-full h-64 sm:h-72">
        {data.length === 0 ? (
          <div className="w-full h-full flex flex-col items-center justify-center text-gray-400 text-xs">
            <p>Waiting for bandwidth telemetry...</p>
            <span className="text-[11px] text-gray-500 mt-1">
              {isMonitoring ? 'Initial throughput baseline establishing' : 'Monitoring currently paused'}
            </span>
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="downloadGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#10b981" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#10b981" stopOpacity={0.0} />
                </linearGradient>
                <linearGradient id="uploadGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#0d6efd" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#0d6efd" stopOpacity={0.0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(200, 215, 240, 0.15)" vertical={false} />
              <XAxis
                dataKey="time"
                stroke="#64748b"
                tick={{ fontSize: 10, fontFamily: 'monospace' }}
                tickLine={false}
                axisLine={false}
              />
              <YAxis
                stroke="#64748b"
                domain={[0, maxVal]}
                tick={{ fontSize: 10, fontFamily: 'monospace' }}
                tickLine={false}
                axisLine={false}
                unit="M"
              />
              <Tooltip content={<CustomTooltip />} />
              <Legend
                verticalAlign="top"
                align="right"
                iconType="circle"
                wrapperStyle={{ paddingBottom: '10px', fontSize: '12px' }}
              />
              <Area
                type="monotone"
                dataKey="downloadMbps"
                name="Download (Mbps)"
                stroke="#10b981"
                strokeWidth={2}
                fillOpacity={1}
                fill="url(#downloadGrad)"
                isAnimationActive={false}
              />
              <Area
                type="monotone"
                dataKey="uploadMbps"
                name="Upload (Mbps)"
                stroke="#0d6efd"
                strokeWidth={2}
                fillOpacity={1}
                fill="url(#uploadGrad)"
                isAnimationActive={false}
              />
            </AreaChart>
          </ResponsiveContainer>
        )}
      </div>

      <div className="mt-3 pt-3 border-t border-cyber-border/30 flex items-center justify-between text-[11px] text-gray-500 font-mono">
        <span>History: Last {data.length}s</span>
        <span>Peak Down: {peakDown.toFixed(2)} Mbps | Peak Up: {peakUp.toFixed(2)} Mbps</span>
      </div>
    </div>
  )
}
export default TrafficChart
