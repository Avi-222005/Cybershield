import React from 'react'
import type { PacketEvent } from '../../types/networkMonitor'
import { Activity, ArrowDownLeft, ArrowUpRight, Repeat, HelpCircle, Shield } from 'lucide-react'
import { cn } from '../../lib/utils'

interface RecentActivityProps {
  events: PacketEvent[]
  className?: string
}

export function RecentActivity({ events, className }: RecentActivityProps) {
  const getDirectionBadge = (dir: string) => {
    const d = (dir || 'unknown').toLowerCase()
    if (d === 'outbound') {
      return {
        label: 'OUT',
        color: 'bg-[#0d6efd]/10 text-[#0d6efd] border-[#0d6efd]/30',
        icon: ArrowUpRight,
      }
    }
    if (d === 'inbound') {
      return {
        label: 'IN',
        color: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
        icon: ArrowDownLeft,
      }
    }
    if (d === 'internal') {
      return {
        label: 'INT',
        color: 'bg-purple-500/10 text-purple-400 border-purple-500/30',
        icon: Repeat,
      }
    }
    return {
      label: 'UNK',
      color: 'bg-gray-500/10 text-gray-400 border-gray-500/30',
      icon: HelpCircle,
    }
  }

  const formatTime = (ts: number) => {
    if (!ts) return '-'
    const d = new Date(ts * 1000)
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
  }

  return (
    <div className={cn('glass-card rounded-2xl border border-cyber-border overflow-hidden', className)}>
      <div className="p-4 sm:p-5 border-b border-cyber-border/40 flex items-center justify-between">
        <div>
          <h3 className="text-base font-bold text-gray-900 dark:text-white flex items-center gap-2">
            <Activity size={18} className="text-[#0d6efd]" />
            Recent Network Traffic Metadata
          </h3>
          <p className="text-xs text-gray-400 mt-0.5">
            Real-time packet events (Payloads are strictly excluded by privacy policy)
          </p>
        </div>
        <span className="text-xs font-mono text-gray-400 bg-cyber-surface/60 px-2.5 py-1 rounded-lg border border-cyber-border/40">
          Showing {events.length} events
        </span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse text-xs font-mono">
          <thead>
            <tr className="border-b border-cyber-border/40 bg-cyber-surface/40 text-gray-400 font-medium select-none">
              <th className="py-2.5 px-4">TIME</th>
              <th className="py-2.5 px-4">SOURCE ENDPOINT</th>
              <th className="py-2.5 px-4">DESTINATION ENDPOINT</th>
              <th className="py-2.5 px-4">PROTO</th>
              <th className="py-2.5 px-4">DIR</th>
              <th className="py-2.5 px-4 text-right">SIZE</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-cyber-border/20">
            {events.length === 0 ? (
              <tr>
                <td colSpan={6} className="py-10 text-center text-gray-500">
                  No network packet metadata captured in current session
                </td>
              </tr>
            ) : (
              events.slice(-15).reverse().map((ev, idx) => {
                const dirBadge = getDirectionBadge(ev.direction)
                const DirIcon = dirBadge.icon

                const src = ev.source_port ? `${ev.source_ip}:${ev.source_port}` : (ev.source_ip || 'N/A')
                const dst = ev.destination_port ? `${ev.destination_ip}:${ev.destination_port}` : (ev.destination_ip || 'N/A')

                return (
                  <tr key={`${ev.timestamp}-${idx}`} className="hover:bg-cyber-surface/60 transition-colors">
                    <td className="py-2 px-4 text-gray-400">{formatTime(ev.timestamp)}</td>
                    <td className="py-2 px-4 text-gray-200">{src}</td>
                    <td className="py-2 px-4 text-gray-200">{dst}</td>
                    <td className="py-2 px-4">
                      <span className="px-1.5 py-0.5 rounded text-[11px] font-bold bg-[#0d6efd]/10 text-[#0d6efd] border border-[#0d6efd]/30">
                        {ev.protocol}
                      </span>
                    </td>
                    <td className="py-2 px-4">
                      <span
                        className={cn(
                          'inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold border',
                          dirBadge.color
                        )}
                      >
                        <DirIcon size={10} />
                        {dirBadge.label}
                      </span>
                    </td>
                    <td className="py-2 px-4 text-right text-gray-400 font-mono">
                      {ev.packet_size.toLocaleString()} B
                    </td>
                  </tr>
                )
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
export default RecentActivity
