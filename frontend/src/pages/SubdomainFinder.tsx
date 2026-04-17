import { useMemo, useState, FormEvent } from 'react'
import { Search, Network, ShieldAlert, Radio, Filter, Download } from 'lucide-react'
import PageWrapper from '../components/ui/PageWrapper'
import LoadingSpinner from '../components/ui/LoadingSpinner'
import { subdomainFinderPro } from '../lib/api'
import type { SubdomainFinderProResult, SubdomainScanMode } from '../types'

type DisplayRow = {
  host: string
  ip: string | null
  status: 'Live' | 'Dead' | 'Redirect' | 'Timeout' | 'Historical'
  http_code: number | null
  title: string
  tech: string[]
  risk: 'LOW' | 'MEDIUM' | 'HIGH'
  issues: string[]
  sources: string[]
}

const SCAN_MODE_OPTIONS: Array<{ value: SubdomainScanMode; label: string; helper: string }> = [
  { value: 'light', label: 'Light', helper: 'Fast passive scan + small DNS wordlist' },
  { value: 'standard', label: 'Standard', helper: 'Balanced coverage with JS, wordlist, and mutations' },
  { value: 'deep', label: 'Deep', helper: 'Maximum coverage with reverse hints and historical tracking' },
]

export default function SubdomainFinder() {
  const [domain, setDomain] = useState('')
  const [scanMode, setScanMode] = useState<SubdomainScanMode>('standard')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<SubdomainFinderProResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [showLiveOnly, setShowLiveOnly] = useState(false)
  const [showHighRiskOnly, setShowHighRiskOnly] = useState(false)
  const [showHistoricalOnly, setShowHistoricalOnly] = useState(false)
  const [searchHost, setSearchHost] = useState('')

  async function onSubmit(e: FormEvent) {
    e.preventDefault()
    if (!domain.trim()) return
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      setResult(await subdomainFinderPro(domain.trim(), scanMode))
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Subdomain Finder Pro scan failed')
    } finally {
      setLoading(false)
    }
  }

  const displayRows = useMemo<DisplayRow[]>(() => {
    if (!result) return []

    const activeRows: DisplayRow[] = result.subdomains.map((row) => ({
      host: row.host,
      ip: row.ip,
      status: row.status,
      http_code: row.http_code,
      title: row.title,
      tech: row.tech,
      risk: row.risk,
      issues: row.issues,
      sources: row.sources,
    }))

    const historicalRows: DisplayRow[] = result.historical_candidates.map((entry) => ({
      host: entry.host,
      ip: null,
      status: 'Historical',
      http_code: null,
      title: entry.reason,
      tech: [],
      risk: entry.risk,
      issues: entry.issues,
      sources: entry.sources,
    }))

    return [...activeRows, ...historicalRows]
  }, [result])

  const filteredRows = useMemo(() => {
    return displayRows.filter((row) => {
      if (showHistoricalOnly && row.status !== 'Historical') return false
      if (!showHistoricalOnly && row.status === 'Historical') return false
      if (showLiveOnly && !(row.status === 'Live' || row.status === 'Redirect')) return false
      if (showHighRiskOnly && row.risk !== 'HIGH') return false
      if (searchHost.trim() && !row.host.toLowerCase().includes(searchHost.trim().toLowerCase())) return false
      return true
    })
  }, [displayRows, showHistoricalOnly, showLiveOnly, showHighRiskOnly, searchHost])

  const highRiskHosts = useMemo(
    () => filteredRows.filter((item) => item.risk === 'HIGH').slice(0, 12),
    [filteredRows],
  )

  const allIssues = useMemo(() => {
    const merged = new Set<string>()
    filteredRows.forEach((item) => item.issues.forEach((issue) => merged.add(issue)))
    return Array.from(merged)
  }, [filteredRows])

  function downloadText(filename: string, content: string, mime: string) {
    const blob = new Blob([content], { type: mime })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = filename
    document.body.appendChild(anchor)
    anchor.click()
    anchor.remove()
    URL.revokeObjectURL(url)
  }

  function exportJson() {
    if (!result) return
    downloadText(
      `subdomain-finder-pro-${result.target}-${result.scan_mode}.json`,
      JSON.stringify(result, null, 2),
      'application/json',
    )
  }

  function csvCell(value: string) {
    return `"${String(value).replace(/"/g, '""')}"`
  }

  function exportCsv() {
    if (filteredRows.length === 0) return

    const header = ['Host', 'IP', 'Status', 'Code', 'Title', 'Tech', 'Risk', 'Issues', 'Sources']
    const lines = [header.map(csvCell).join(',')]
    for (const row of filteredRows) {
      lines.push(
        [
          row.host,
          row.ip || '',
          row.status,
          row.http_code?.toString() || '',
          row.title,
          row.tech.join('; '),
          row.risk,
          row.issues.join('; '),
          row.sources.join('; '),
        ].map(csvCell).join(','),
      )
    }

    downloadText(
      `subdomain-finder-pro-${domain.trim() || 'target'}-${scanMode}.csv`,
      lines.join('\n'),
      'text/csv;charset=utf-8',
    )
  }

  function riskBadge(risk: 'LOW' | 'MEDIUM' | 'HIGH') {
    if (risk === 'HIGH') return 'bg-red-500/20 text-red-300 border border-red-400/40'
    if (risk === 'MEDIUM') return 'bg-amber-500/20 text-amber-300 border border-amber-400/40'
    return 'bg-emerald-500/20 text-emerald-300 border border-emerald-400/40'
  }

  function statusBadge(status: string) {
    if (status === 'Historical') return 'bg-violet-500/15 text-violet-300 border border-violet-400/40'
    if (status === 'Live') return 'bg-emerald-500/15 text-emerald-300 border border-emerald-400/40'
    if (status === 'Redirect') return 'bg-cyan-500/15 text-cyan-300 border border-cyan-400/40'
    if (status === 'Timeout') return 'bg-amber-500/15 text-amber-300 border border-amber-400/40'
    return 'bg-white/10 text-gray-300 border border-white/15'
  }

  function hostUrl(host: string) {
    return /^https?:\/\//i.test(host) ? host : `https://${host}`
  }

  return (
    <PageWrapper>
      <div className="max-w-7xl mx-auto px-4 sm:px-6 pt-28 pb-20">
        <div className="mb-8 flex items-center gap-2.5">
          <div className="p-2 rounded-lg bg-[#0d6efd]/10 border border-[#0d6efd]/20">
            <Network size={18} className="text-[#0d6efd]" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white">Subdomain Finder Pro</h1>
            <p className="text-xs text-gray-400 font-mono mt-1">Hybrid Attack Surface Discovery Engine</p>
          </div>
        </div>

        <form onSubmit={onSubmit} className="glass-card rounded-2xl p-5 mb-6">
          <div className="grid md:grid-cols-4 gap-3">
            <input
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="example.com"
              className="cyber-input md:col-span-2 px-4 py-3 rounded-xl text-sm font-mono"
            />
            <select
              value={scanMode}
              onChange={(e) => setScanMode(e.target.value as SubdomainScanMode)}
              className="cyber-input px-4 py-3 rounded-xl text-sm font-mono"
            >
              {SCAN_MODE_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>{option.label}</option>
              ))}
            </select>
            <button className="inline-flex w-fit justify-self-start items-center gap-2 px-4 py-2.5 bg-[#0d6efd] hover:bg-[#0b5ed7] !text-white font-semibold rounded-xl text-sm">
              <Search size={16} />
              Discover
            </button>
          </div>
          <p className="text-xs text-gray-500 font-mono mt-2">
            {SCAN_MODE_OPTIONS.find((x) => x.value === scanMode)?.helper}
          </p>
        </form>

        {loading && <div className="glass-card rounded-2xl"><LoadingSpinner label="Running passive + active-safe discovery..." /></div>}
        {error && <div className="glass-card rounded-2xl p-5 border border-red-500/25 bg-red-500/5 text-red-400 text-sm font-mono">{error}</div>}

        {result && (
          <div className="space-y-6">
            <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
              <div className="glass-card rounded-xl p-4">
                <div className="text-xs text-gray-400 font-mono">Total Found</div>
                <div className="text-2xl text-white font-bold mt-1">{result.total_found}</div>
              </div>
              <div className="glass-card rounded-xl p-4">
                <div className="text-xs text-gray-400 font-mono">Validated</div>
                <div className="text-2xl text-white font-bold mt-1">{result.validated}</div>
              </div>
              <div className="glass-card rounded-xl p-4">
                <div className="text-xs text-gray-400 font-mono">Live Hosts</div>
                <div className="text-2xl text-white font-bold mt-1">{result.live_hosts}</div>
              </div>
              <div className="glass-card rounded-xl p-4">
                <div className="text-xs text-gray-400 font-mono">High Risk</div>
                <div className="text-2xl text-red-300 font-bold mt-1">{result.high_risk}</div>
              </div>
              <div className="glass-card rounded-xl p-4">
                <div className="text-xs text-gray-400 font-mono">Sources Used</div>
                <div className="text-lg text-white font-semibold mt-1">{result.sources_used.length}</div>
                <div className="text-[11px] text-gray-500 font-mono mt-1">Grade {result.grade} ({result.score})</div>
              </div>
              <div className="glass-card rounded-xl p-4 col-span-2 lg:col-span-1">
                <div className="text-xs text-gray-400 font-mono">Historical Unresolved</div>
                <div className="text-2xl text-violet-300 font-bold mt-1">{result.historical_unresolved}</div>
                <div className="text-[11px] text-gray-500 font-mono mt-1">{result.grade_label}</div>
              </div>
            </div>

            <div className="glass-card rounded-2xl p-5">
              <div className="flex items-center gap-2 mb-4">
                <Filter size={15} className="text-[#0d6efd]" />
                <h2 className="text-sm font-semibold text-white">Filters</h2>
              </div>
              <div className="grid md:grid-cols-3 gap-3">
                <label className="flex items-center gap-2 text-sm text-gray-200">
                  <input
                    type="checkbox"
                    checked={showLiveOnly}
                    onChange={(e) => setShowLiveOnly(e.target.checked)}
                    className="accent-[#0d6efd]"
                  />
                  Live only
                </label>
                <label className="flex items-center gap-2 text-sm text-gray-200">
                  <input
                    type="checkbox"
                    checked={showHighRiskOnly}
                    onChange={(e) => setShowHighRiskOnly(e.target.checked)}
                    className="accent-[#0d6efd]"
                  />
                  High risk only
                </label>
                <label className="flex items-center gap-2 text-sm text-gray-200">
                  <input
                    type="checkbox"
                    checked={showHistoricalOnly}
                    onChange={(e) => setShowHistoricalOnly(e.target.checked)}
                    className="accent-[#0d6efd]"
                  />
                  Historical only
                </label>
                <input
                  value={searchHost}
                  onChange={(e) => setSearchHost(e.target.value)}
                  placeholder="Search host"
                  className="cyber-input px-3 py-2 rounded-lg text-sm font-mono"
                />
              </div>
              <div className="flex flex-wrap gap-2 mt-3">
                <button
                  type="button"
                  onClick={exportCsv}
                  disabled={filteredRows.length === 0}
                  className="px-3 py-2 rounded-lg text-xs border border-white/20 text-gray-200 disabled:opacity-40 flex items-center gap-1"
                >
                  <Download size={13} /> Export CSV
                </button>
                <button
                  type="button"
                  onClick={exportJson}
                  disabled={!result}
                  className="px-3 py-2 rounded-lg text-xs border border-white/20 text-gray-200 disabled:opacity-40 flex items-center gap-1"
                >
                  <Download size={13} /> Export JSON
                </button>
              </div>
            </div>

            <div className="glass-card rounded-2xl p-5 overflow-auto">
              <div className="text-sm text-gray-300 font-semibold mb-3">Subdomain Results ({filteredRows.length})</div>
              <table className="w-full text-sm min-w-[960px]">
                <thead>
                  <tr className="text-left text-gray-400 border-b border-white/10">
                    <th className="py-2 pr-3">Host</th>
                    <th className="py-2 pr-3">IP</th>
                    <th className="py-2 pr-3">Status</th>
                    <th className="py-2 pr-3">Code</th>
                    <th className="py-2 pr-3">Title</th>
                    <th className="py-2 pr-3">Tech</th>
                    <th className="py-2 pr-3">Risk</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredRows.length > 0 ? (
                    filteredRows.map((row) => (
                      <tr key={row.host} className="border-b border-white/5 align-top">
                        <td className="py-2 pr-3 text-gray-100 font-mono">
                          <a
                            href={hostUrl(row.host)}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-[#6ea8fe] hover:text-[#9ec5fe] underline underline-offset-2"
                          >
                            {row.host}
                          </a>
                        </td>
                        <td className="py-2 pr-3 text-gray-400 font-mono">{row.ip || '-'}</td>
                        <td className="py-2 pr-3">
                          <span className={`px-2 py-1 rounded-md text-xs font-semibold ${statusBadge(row.status)}`}>
                            {row.status}
                          </span>
                        </td>
                        <td className="py-2 pr-3 text-gray-300 font-mono">{row.http_code ?? '-'}</td>
                        <td className="py-2 pr-3 text-gray-300 max-w-[240px] truncate" title={row.title || ''}>{row.title || '-'}</td>
                        <td className="py-2 pr-3 text-gray-300">{row.tech.length > 0 ? row.tech.join(', ') : '-'}</td>
                        <td className="py-2 pr-3">
                          <span className={`px-2 py-1 rounded-md text-xs font-semibold ${riskBadge(row.risk)}`}>
                            {row.risk}
                          </span>
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={7} className="py-4 text-center text-gray-500 font-mono">No hosts match current filters</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>

            <div className="grid lg:grid-cols-2 gap-4">
              <div className="glass-card rounded-2xl p-5">
                <div className="flex items-center gap-2 mb-3">
                  <ShieldAlert size={16} className="text-red-300" />
                  <h3 className="text-sm font-semibold text-white">Risk Signals</h3>
                </div>
                <div className="space-y-2">
                  {highRiskHosts.length > 0 ? (
                    highRiskHosts.map((host) => (
                      <div key={host.host} className="bg-white/5 rounded-lg px-3 py-2">
                        <div className="text-sm text-gray-100 font-mono">{host.host}</div>
                        <div className="text-xs text-red-300 mt-1">{host.issues.join(', ') || 'High risk exposure pattern'}</div>
                      </div>
                    ))
                  ) : (
                    <div className="text-sm text-gray-500 font-mono">No high-risk hosts detected.</div>
                  )}

                  {allIssues.length > 0 && (
                    <div className="pt-2">
                      <div className="text-xs text-gray-400 font-mono mb-1">Detected Issues</div>
                      <div className="text-xs text-gray-300 font-mono">{allIssues.join(' | ')}</div>
                    </div>
                  )}
                </div>
              </div>

              <div className="glass-card rounded-2xl p-5">
                <div className="flex items-center gap-2 mb-3">
                  <Radio size={16} className="text-cyan-300" />
                  <h3 className="text-sm font-semibold text-white">Recommendations</h3>
                </div>
                <div className="space-y-2">
                  {result.recommendations.map((rec, index) => (
                    <div key={index} className="bg-white/5 rounded-lg px-3 py-2 text-sm text-gray-200">{rec}</div>
                  ))}
                </div>

                <div className="mt-4 pt-3 border-t border-white/10 text-xs text-gray-400 font-mono">
                  Sources: {result.sources_used.join(', ') || 'None'}
                </div>
                <div className="text-xs text-gray-500 font-mono mt-1">
                  Wildcard DNS: {result.wildcard_dns ? 'Detected' : 'Not detected'}
                </div>
                {result.cached && (
                  <div className="text-xs text-gray-500 font-mono mt-1">
                    Cache: response served from short-term scan cache
                  </div>
                )}
              </div>
            </div>

            {Object.keys(result.source_errors || {}).length > 0 && (
              <div className="glass-card rounded-2xl p-5 border border-amber-500/20 bg-amber-500/5">
                <div className="text-sm text-amber-300 font-semibold mb-2">Partial Source Errors</div>
                <div className="space-y-1">
                  {Object.entries(result.source_errors).map(([source, message]) => (
                    <div key={source} className="text-xs text-amber-200 font-mono">
                      {source}: {message}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </PageWrapper>
  )
}
