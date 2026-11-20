import React, { useMemo, useState } from 'react'
import type { NetworkConnection } from '../../types/networkMonitor'
import {
  Search,
  Filter,
  ArrowUpDown,
  ExternalLink,
  X,
  Server,
  Cpu,
  Shield,
  Activity,
  Layers,
} from 'lucide-react'
import { cn } from '../../lib/utils'

interface ConnectionTableProps {
  connections: NetworkConnection[]
  isLoading?: boolean
  error?: string | null
  onRefresh?: () => void
}

type SortField = 'local' | 'remote' | 'protocol' | 'status' | 'pid' | 'process_name'
type SortOrder = 'asc' | 'desc'

export function ConnectionTable({
  connections,
  isLoading = false,
  error = null,
  onRefresh,
}: ConnectionTableProps) {
  const [search, setSearch] = useState('')
  const [protoFilter, setProtoFilter] = useState<'ALL' | 'TCP' | 'UDP'>('ALL')
  const [statusFilter, setStatusFilter] = useState<string>('ALL')
  const [sortField, setSortField] = useState<SortField>('status')
  const [sortOrder, setSortOrder] = useState<SortOrder>('asc')
  const [selectedConn, setSelectedConn] = useState<NetworkConnection | null>(null)
  const [pageSize, setPageSize] = useState<number>(15)
  const [currentPage, setCurrentPage] = useState<number>(1)

  // Extract unique statuses for dropdown
  const uniqueStatuses = useMemo(() => {
    const set = new Set<string>()
    connections.forEach((c) => {
      if (c.status) set.add(c.status)
    })
    return Array.from(set).sort()
  }, [connections])

  // Filter and sort connections
  const filteredConnections = useMemo(() => {
    const q = search.trim().toLowerCase()
    return connections
      .filter((c) => {
        // Protocol filter
        if (protoFilter !== 'ALL' && c.protocol.toUpperCase() !== protoFilter) {
          return false
        }
        // Status filter
        if (statusFilter !== 'ALL' && c.status !== statusFilter) {
          return false
        }
        // Text search
        if (q) {
          const matchLocal = `${c.local_ip}:${c.local_port}`.toLowerCase().includes(q)
          const matchRemote = `${c.remote_ip}:${c.remote_port}`.toLowerCase().includes(q)
          const matchProc = (c.process_name || '').toLowerCase().includes(q)
          const matchPid = c.pid ? String(c.pid).includes(q) : false
          const matchStatus = c.status.toLowerCase().includes(q)
          if (!matchLocal && !matchRemote && !matchProc && !matchPid && !matchStatus) {
            return false
          }
        }
        return true
      })
      .sort((a, b) => {
        let valA: any = ''
        let valB: any = ''
        if (sortField === 'local') {
          valA = `${a.local_ip}:${a.local_port}`
          valB = `${b.local_ip}:${b.local_port}`
        } else if (sortField === 'remote') {
          valA = `${a.remote_ip}:${a.remote_port}`
          valB = `${b.remote_ip}:${b.remote_port}`
        } else if (sortField === 'protocol') {
          valA = a.protocol
          valB = b.protocol
        } else if (sortField === 'status') {
          valA = a.status
          valB = b.status
        } else if (sortField === 'pid') {
          valA = a.pid || 0
          valB = b.pid || 0
        } else if (sortField === 'process_name') {
          valA = a.process_name || 'zzz'
          valB = b.process_name || 'zzz'
        }

        if (valA < valB) return sortOrder === 'asc' ? -1 : 1
        if (valA > valB) return sortOrder === 'asc' ? 1 : -1
        return 0
      })
  }, [connections, search, protoFilter, statusFilter, sortField, sortOrder])

  // Pagination
  const totalPages = Math.ceil(filteredConnections.length / pageSize) || 1
  const paginatedConnections = useMemo(() => {
    const start = (currentPage - 1) * pageSize
    return filteredConnections.slice(start, start + pageSize)
  }, [filteredConnections, currentPage, pageSize])

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortOrder((prev) => (prev === 'asc' ? 'desc' : 'asc'))
    } else {
      setSortField(field)
      setSortOrder('asc')
    }
  }

  const getStatusBadge = (status: string) => {
    const s = status.toUpperCase()
    if (s === 'ESTABLISHED') {
      return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
    }
    if (s === 'LISTEN') {
      return 'bg-[#0d6efd]/10 text-[#0d6efd] border-[#0d6efd]/30'
    }
    if (s.includes('WAIT')) {
      return 'bg-amber-500/10 text-amber-400 border-amber-500/30'
    }
    if (s.includes('CLOSE')) {
      return 'bg-rose-500/10 text-rose-400 border-rose-500/30'
    }
    return 'bg-gray-500/10 text-gray-400 border-gray-500/30'
  }

  return (
    <div className="glass-card rounded-2xl border border-cyber-border overflow-hidden flex flex-col">
      {/* Controls Bar */}
      <div className="p-4 sm:p-5 border-b border-cyber-border/40 flex flex-col md:flex-row gap-3 md:items-center justify-between">
        {/* Search */}
        <div className="relative flex-1 max-w-md">
          <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
          <input
            type="text"
            value={search}
            onChange={(e) => {
              setSearch(e.target.value)
              setCurrentPage(1)
            }}
            placeholder="Filter by IP, port, status, or process name..."
            className="w-full pl-9 pr-4 py-2 rounded-xl text-xs sm:text-sm cyber-input font-mono focus:outline-none focus:border-[#0d6efd]/60"
          />
          {search && (
            <button
              onClick={() => setSearch('')}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-white"
            >
              <X size={14} />
            </button>
          )}
        </div>

        {/* Filter Pills */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Protocol Toggle */}
          <div className="flex rounded-xl bg-cyber-surface/80 border border-cyber-border/60 p-0.5 text-xs font-mono">
            {(['ALL', 'TCP', 'UDP'] as const).map((proto) => (
              <button
                key={proto}
                onClick={() => {
                  setProtoFilter(proto)
                  setCurrentPage(1)
                }}
                className={cn(
                  'px-2.5 py-1 rounded-lg transition-colors font-medium',
                  protoFilter === proto
                    ? 'bg-[#0d6efd] text-white shadow-sm'
                    : 'text-gray-400 hover:text-white'
                )}
              >
                {proto}
              </button>
            ))}
          </div>

          {/* Status Dropdown */}
          <select
            value={statusFilter}
            onChange={(e) => {
              setStatusFilter(e.target.value)
              setCurrentPage(1)
            }}
            className="px-2.5 py-1.5 rounded-xl text-xs cyber-input font-mono focus:outline-none"
          >
            <option value="ALL">All States ({connections.length})</option>
            {uniqueStatuses.map((st) => (
              <option key={st} value={st}>
                {st}
              </option>
            ))}
          </select>

          {/* Results count */}
          <span className="text-xs text-gray-400 font-mono hidden sm:inline-block ml-2">
            Showing {filteredConnections.length} of {connections.length}
          </span>
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse text-xs font-mono">
          <thead>
            <tr className="border-b border-cyber-border/40 bg-cyber-surface/40 text-gray-400 font-medium select-none">
              <th className="py-3 px-4">
                <button
                  onClick={() => handleSort('protocol')}
                  className="flex items-center gap-1 hover:text-white"
                >
                  PROTO <ArrowUpDown size={12} />
                </button>
              </th>
              <th className="py-3 px-4">
                <button
                  onClick={() => handleSort('local')}
                  className="flex items-center gap-1 hover:text-white"
                >
                  LOCAL ENDPOINT <ArrowUpDown size={12} />
                </button>
              </th>
              <th className="py-3 px-4">
                <button
                  onClick={() => handleSort('remote')}
                  className="flex items-center gap-1 hover:text-white"
                >
                  REMOTE ENDPOINT <ArrowUpDown size={12} />
                </button>
              </th>
              <th className="py-3 px-4">
                <button
                  onClick={() => handleSort('status')}
                  className="flex items-center gap-1 hover:text-white"
                >
                  STATUS <ArrowUpDown size={12} />
                </button>
              </th>
              <th className="py-3 px-4">
                <button
                  onClick={() => handleSort('pid')}
                  className="flex items-center gap-1 hover:text-white"
                >
                  PID <ArrowUpDown size={12} />
                </button>
              </th>
              <th className="py-3 px-4">
                <button
                  onClick={() => handleSort('process_name')}
                  className="flex items-center gap-1 hover:text-white"
                >
                  PROCESS <ArrowUpDown size={12} />
                </button>
              </th>
              <th className="py-3 px-4 text-right">ACTION</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-cyber-border/20">
            {paginatedConnections.length === 0 ? (
              <tr>
                <td colSpan={7} className="py-12 text-center text-gray-500">
                  {connections.length === 0
                    ? 'No active internet socket connections detected'
                    : 'No connections match the current search filter'}
                </td>
              </tr>
            ) : (
              paginatedConnections.map((conn, idx) => {
                const isSelected =
                  selectedConn &&
                  selectedConn.local_ip === conn.local_ip &&
                  selectedConn.local_port === conn.local_port &&
                  selectedConn.remote_ip === conn.remote_ip &&
                  selectedConn.remote_port === conn.remote_port

                return (
                  <tr
                    key={`${conn.protocol}-${conn.local_ip}:${conn.local_port}-${conn.remote_ip}:${conn.remote_port}-${idx}`}
                    onClick={() => setSelectedConn(conn)}
                    className={cn(
                      'hover:bg-cyber-surface/60 transition-colors cursor-pointer group',
                      isSelected && 'bg-[#0d6efd]/10'
                    )}
                  >
                    <td className="py-2.5 px-4">
                      <span className="font-bold text-gray-300 uppercase">{conn.protocol}</span>
                    </td>
                    <td className="py-2.5 px-4 text-gray-200">
                      {conn.local_ip}:{conn.local_port}
                    </td>
                    <td className="py-2.5 px-4 text-gray-300">
                      {conn.remote_ip ? (
                        `${conn.remote_ip}:${conn.remote_port}`
                      ) : (
                        <span className="text-gray-500">*:* (Unconnected)</span>
                      )}
                    </td>
                    <td className="py-2.5 px-4">
                      <span
                        className={cn(
                          'inline-block px-2 py-0.5 rounded-full text-[11px] font-semibold border',
                          getStatusBadge(conn.status)
                        )}
                      >
                        {conn.status}
                      </span>
                    </td>
                    <td className="py-2.5 px-4 text-gray-400">{conn.pid ? conn.pid : 'N/A'}</td>
                    <td className="py-2.5 px-4">
                      {conn.process_name ? (
                        <span className="text-emerald-400 font-semibold">{conn.process_name}</span>
                      ) : (
                        <span className="text-gray-500">N/A</span>
                      )}
                    </td>
                    <td className="py-2.5 px-4 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation()
                          setSelectedConn(conn)
                        }}
                        className="text-gray-400 group-hover:text-[#0d6efd] transition-colors p-1"
                        title="View Details"
                      >
                        <ExternalLink size={14} />
                      </button>
                    </td>
                  </tr>
                )
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Footer */}
      <div className="p-3 sm:p-4 border-t border-cyber-border/40 bg-cyber-surface/30 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs font-mono">
        <div className="text-gray-400">
          Page {currentPage} of {totalPages} ({filteredConnections.length} items)
        </div>

        <div className="flex items-center gap-2">
          <select
            value={pageSize}
            onChange={(e) => {
              setPageSize(Number(e.target.value))
              setCurrentPage(1)
            }}
            className="px-2 py-1 rounded-lg cyber-input text-xs"
          >
            <option value={15}>15 / page</option>
            <option value={30}>30 / page</option>
            <option value={50}>50 / page</option>
            <option value={100}>100 / page</option>
          </select>

          <button
            onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
            disabled={currentPage <= 1}
            className="px-3 py-1 rounded-lg bg-cyber-surface border border-cyber-border/60 text-gray-300 disabled:opacity-40 hover:text-white transition-colors"
          >
            Previous
          </button>
          <button
            onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
            disabled={currentPage >= totalPages}
            className="px-3 py-1 rounded-lg bg-cyber-surface border border-cyber-border/60 text-gray-300 disabled:opacity-40 hover:text-white transition-colors"
          >
            Next
          </button>
        </div>
      </div>

      {/* Detail Drawer / Modal */}
      {selectedConn && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm animate-in fade-in duration-150">
          <div className="glass-card rounded-2xl border border-cyber-border max-w-lg w-full p-6 shadow-2xl relative">
            <button
              onClick={() => setSelectedConn(null)}
              className="absolute top-4 right-4 p-1.5 rounded-lg text-gray-400 hover:text-white hover:bg-white/5"
            >
              <X size={18} />
            </button>

            <div className="flex items-center gap-3 mb-5">
              <div className="w-10 h-10 rounded-xl bg-[#0d6efd]/10 border border-[#0d6efd]/30 text-[#0d6efd] flex items-center justify-center">
                <Activity size={20} />
              </div>
              <div>
                <h3 className="text-base font-bold text-gray-900 dark:text-white font-mono">
                  Socket Connection Details
                </h3>
                <span className="text-xs text-gray-400 font-mono">
                  {selectedConn.protocol.toUpperCase()} Socket Inspection
                </span>
              </div>
            </div>

            <div className="space-y-3 font-mono text-xs">
              <div className="p-3 rounded-xl bg-cyber-surface/60 border border-cyber-border/40 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">Local Endpoint:</span>
                  <span className="font-bold text-gray-200">
                    {selectedConn.local_ip}:{selectedConn.local_port}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">Remote Endpoint:</span>
                  <span className="font-bold text-gray-200">
                    {selectedConn.remote_ip
                      ? `${selectedConn.remote_ip}:${selectedConn.remote_port}`
                      : 'None (*:*)'}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">Socket Protocol:</span>
                  <span className="text-[#0d6efd] font-bold uppercase">{selectedConn.protocol}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">Connection State:</span>
                  <span
                    className={cn(
                      'px-2 py-0.5 rounded-full text-[11px] font-semibold border',
                      getStatusBadge(selectedConn.status)
                    )}
                  >
                    {selectedConn.status}
                  </span>
                </div>
              </div>

              <div className="p-3 rounded-xl bg-cyber-surface/60 border border-cyber-border/40 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">Process Name:</span>
                  <span className="font-bold text-emerald-400">
                    {selectedConn.process_name || 'N/A (Unresolved or System)'}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">Process ID (PID):</span>
                  <span className="text-gray-200">{selectedConn.pid || 'N/A'}</span>
                </div>
                <div className="flex items-center justify-between text-[11px] text-gray-500 pt-1 border-t border-cyber-border/30">
                  <span>Attribution Mode:</span>
                  <span>OS net_connections + Process Cache</span>
                </div>
              </div>
            </div>

            <div className="mt-5 flex justify-end">
              <button
                onClick={() => setSelectedConn(null)}
                className="px-4 py-2 rounded-xl bg-cyber-surface hover:bg-cyber-surface/80 border border-cyber-border text-xs font-semibold text-gray-300"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
export default ConnectionTable
