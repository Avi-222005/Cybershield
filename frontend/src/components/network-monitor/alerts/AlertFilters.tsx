import React from 'react'
import { Search, Filter, RotateCcw } from 'lucide-react'

interface AlertFiltersProps {
  search: string
  onSearchChange: (search: string) => void
  severity: string
  onSeverityChange: (severity: string) => void
  status: string
  onStatusChange: (status: string) => void
  category: string
  onCategoryChange: (category: string) => void
  onReset: () => void
}

export function AlertFilters({
  search,
  onSearchChange,
  severity,
  onSeverityChange,
  status,
  onStatusChange,
  category,
  onCategoryChange,
  onReset,
}: AlertFiltersProps) {
  const hasActiveFilters =
    search.trim() !== '' ||
    severity !== 'ALL' ||
    status !== 'ALL' ||
    category !== 'ALL'

  return (
    <div className="glass-card rounded-2xl border border-cyber-border p-4 flex flex-col md:flex-row gap-3 items-stretch md:items-center justify-between">
      {/* Search Input */}
      <div className="relative flex-1">
        <Search
          size={16}
          className="absolute left-3.5 top-1/2 -translate-y-1/2 text-gray-400 pointer-events-none"
        />
        <input
          type="text"
          value={search}
          onChange={(e) => onSearchChange(e.target.value)}
          placeholder="Filter by title, IP address, rule, or description..."
          className="w-full pl-10 pr-4 py-2 rounded-xl bg-cyber-surface/70 border border-cyber-border text-xs sm:text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:border-[#0d6efd] focus:ring-1 focus:ring-[#0d6efd] font-mono transition-colors"
        />
      </div>

      {/* Dropdown Filters */}
      <div className="flex flex-wrap items-center gap-2">
        {/* Severity */}
        <div className="flex items-center gap-1.5 bg-cyber-surface/70 border border-cyber-border rounded-xl px-2.5 py-1 text-xs font-mono">
          <span className="text-gray-400">Sev:</span>
          <select
            value={severity}
            onChange={(e) => onSeverityChange(e.target.value)}
            className="bg-transparent text-gray-200 focus:outline-none cursor-pointer"
          >
            <option value="ALL">All</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
        </div>

        {/* Status */}
        <div className="flex items-center gap-1.5 bg-cyber-surface/70 border border-cyber-border rounded-xl px-2.5 py-1 text-xs font-mono">
          <span className="text-gray-400">Status:</span>
          <select
            value={status}
            onChange={(e) => onStatusChange(e.target.value)}
            className="bg-transparent text-gray-200 focus:outline-none cursor-pointer"
          >
            <option value="ALL">All</option>
            <option value="NEW">New</option>
            <option value="ACKNOWLEDGED">Acknowledged</option>
            <option value="INVESTIGATING">Investigating</option>
            <option value="RESOLVED">Resolved</option>
            <option value="FALSE_POSITIVE">False Positive</option>
          </select>
        </div>

        {/* Category */}
        <div className="flex items-center gap-1.5 bg-cyber-surface/70 border border-cyber-border rounded-xl px-2.5 py-1 text-xs font-mono">
          <span className="text-gray-400">Category:</span>
          <select
            value={category}
            onChange={(e) => onCategoryChange(e.target.value)}
            className="bg-transparent text-gray-200 focus:outline-none cursor-pointer"
          >
            <option value="ALL">All Categories</option>
            <option value="RECONNAISSANCE">Reconnaissance</option>
            <option value="PORT_SCAN">Port Scan</option>
            <option value="COMMAND_AND_CONTROL">Command & Control</option>
            <option value="EXFILTRATION">Exfiltration</option>
            <option value="DNS_ANOMALY">DNS Anomaly</option>
          </select>
        </div>

        {/* Reset button */}
        {hasActiveFilters && (
          <button
            type="button"
            onClick={onReset}
            className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-xl bg-gray-500/10 hover:bg-gray-500/20 text-gray-400 text-xs font-mono transition-colors"
            title="Reset filters"
          >
            <RotateCcw size={13} />
            <span>Reset</span>
          </button>
        )}
      </div>
    </div>
  )
}
