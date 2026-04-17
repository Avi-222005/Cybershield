import { useState, FormEvent } from 'react'
import { Search, ScanLine, ShieldAlert, ShieldCheck, AlertTriangle, Server } from 'lucide-react'
import PageWrapper from '../components/ui/PageWrapper'
import LoadingSpinner from '../components/ui/LoadingSpinner'
import { advancedScan } from '../lib/api'
import type { AdvancedScanResult, AdvancedScanType } from '../types'

const SCAN_OPTIONS: Array<{ value: AdvancedScanType; label: string; helper: string }> = [
  { value: 'quick', label: 'Quick Scan', helper: 'Top common ports' },
  { value: 'full', label: 'Full Scan', helper: 'Ports 1-1024' },
  { value: 'web', label: 'Web Scan', helper: 'Ports 80, 443, 8080, 8443' },
  { value: 'custom', label: 'Custom Scan', helper: 'Custom range (max 1024 ports)' },
]

function riskPillClass(level: 'LOW' | 'MEDIUM' | 'HIGH') {
  if (level === 'HIGH') return 'text-red-400 border-red-500/30 bg-red-500/10'
  if (level === 'MEDIUM') return 'text-amber-400 border-amber-500/30 bg-amber-500/10'
  return 'text-green-400 border-green-500/30 bg-green-500/10'
}

function statusPillClass(status: 'open' | 'closed' | 'filtered') {
  if (status === 'open') return 'text-green-400 border-green-500/30 bg-green-500/10'
  if (status === 'filtered') return 'text-amber-400 border-amber-500/30 bg-amber-500/10'
  return 'text-gray-400 border-white/10 bg-white/3'
}

export default function PortScanner() {
  const [target, setTarget] = useState('')
  const [scanType, setScanType] = useState<AdvancedScanType>('quick')
  const [customRange, setCustomRange] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<AdvancedScanResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  async function onSubmit(e: FormEvent) {
    e.preventDefault()
    const trimmedTarget = target.trim()
    if (!trimmedTarget) return

    if (scanType === 'custom' && !customRange.trim()) {
      setError('Custom range is required for custom scan. Example: 1000-2000 or 80,443,8080')
      return
    }

    setLoading(true)
    setError(null)
    setResult(null)

    try {
      const scanResult = await advancedScan(trimmedTarget, scanType, customRange.trim())
      setResult(scanResult)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Advanced scan failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <PageWrapper>
      <div className="max-w-6xl mx-auto px-4 sm:px-6 pt-28 pb-20">
        <div className="mb-8 flex items-center gap-2.5">
          <div className="p-2 rounded-lg bg-[#0d6efd]/10 border border-[#0d6efd]/20">
            <ScanLine size={18} className="text-[#0d6efd]" />
          </div>
          <h1 className="text-2xl font-bold text-white">Advanced Network Scanner</h1>
        </div>

        <div className="glass-card rounded-2xl p-4 mb-5 border border-amber-500/25 bg-amber-500/5">
          <p className="text-amber-300 text-sm font-mono flex items-start gap-2">
            <ShieldAlert size={16} className="mt-0.5 shrink-0" />
            Use only on authorized systems. Unauthorized scanning may be illegal.
          </p>
        </div>

        <form onSubmit={onSubmit} className="glass-card rounded-2xl p-5 mb-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mb-3">
            <div className="md:col-span-2">
              <label className="block text-xs font-mono text-gray-400 mb-2 uppercase tracking-wider">
                Target (Domain, IPv4, or IPv6)
              </label>
              <input
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="example.com or 8.8.8.8"
                className="cyber-input w-full px-4 py-3 rounded-xl text-sm font-mono"
                disabled={loading}
              />
            </div>
            <div>
              <label className="block text-xs font-mono text-gray-400 mb-2 uppercase tracking-wider">
                Scan Profile
              </label>
              <select
                value={scanType}
                onChange={(e) => setScanType(e.target.value as AdvancedScanType)}
                className="cyber-input w-full px-4 py-3 rounded-xl text-sm font-mono"
                disabled={loading}
              >
                {SCAN_OPTIONS.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {scanType === 'custom' && (
            <div className="mb-3">
              <label className="block text-xs font-mono text-gray-400 mb-2 uppercase tracking-wider">
                Custom Range
              </label>
              <input
                value={customRange}
                onChange={(e) => setCustomRange(e.target.value)}
                placeholder="1000-2000 or 80,443,8443"
                className="cyber-input w-full px-4 py-3 rounded-xl text-sm font-mono"
                disabled={loading}
              />
            </div>
          )}

          <div className="flex items-center justify-between gap-3 flex-wrap">
            <p className="text-xs text-gray-500 font-mono">
              {SCAN_OPTIONS.find((x) => x.value === scanType)?.helper} | Max {1024} ports | Timeout 1s/port
            </p>
            <button
              type="submit"
              disabled={loading || !target.trim()}
              className="flex items-center gap-2 px-6 py-3 bg-[#0d6efd] hover:bg-[#0b5ed7] disabled:opacity-50 disabled:cursor-not-allowed !text-white font-semibold rounded-xl text-sm"
            >
              <Search size={16} />
              Start Scan
            </button>
          </div>
        </form>

        {loading && (
          <div className="glass-card rounded-2xl">
            <LoadingSpinner label={`Running ${scanType} profile scan...`} />
          </div>
        )}

        {error && (
          <div className="glass-card rounded-2xl p-5 border border-red-500/25 bg-red-500/5 text-red-400 text-sm font-mono">
            {error}
          </div>
        )}

        {result && (
          <div className="space-y-5">
            <div className="glass-card rounded-2xl p-5">
              <div className="flex items-center justify-between gap-3 flex-wrap mb-3">
                <div>
                  <h2 className="text-lg font-semibold text-white mb-1">Advanced Scan Summary</h2>
                  <p className="text-xs text-gray-500 font-mono">{result.summary}</p>
                </div>
                <span className={`text-xs font-mono px-2.5 py-1 rounded border ${riskPillClass(result.risk_level)}`}>
                  Risk {result.risk_level}
                </span>
              </div>

              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <div className="rounded-xl border border-white/10 bg-white/3 p-3">
                  <div className="text-[10px] text-gray-500 uppercase font-mono">Target</div>
                  <div className="text-sm text-white font-mono break-all">{result.target}</div>
                </div>
                <div className="rounded-xl border border-white/10 bg-white/3 p-3">
                  <div className="text-[10px] text-gray-500 uppercase font-mono">Resolved IP</div>
                  <div className="text-sm text-blue-300 font-mono break-all">{result.resolved_ip}</div>
                </div>
                <div className="rounded-xl border border-white/10 bg-white/3 p-3">
                  <div className="text-[10px] text-gray-500 uppercase font-mono">Open Ports</div>
                  <div className="text-sm text-white font-mono">{result.open_ports} / {result.ports_scanned}</div>
                </div>
                <div className="rounded-xl border border-white/10 bg-white/3 p-3">
                  <div className="text-[10px] text-gray-500 uppercase font-mono">OS Guess</div>
                  <div className="text-sm text-white font-mono">{result.os_guess}</div>
                </div>
              </div>

              <div className="mt-4 flex flex-wrap gap-2 items-center">
                <Server size={14} className="text-gray-500" />
                {result.services.length > 0 ? (
                  result.services.map((svc) => (
                    <span key={svc} className="text-xs font-mono px-2 py-1 rounded border border-[#0d6efd]/25 bg-[#0d6efd]/10 text-[#6ea8fe]">
                      {svc}
                    </span>
                  ))
                ) : (
                  <span className="text-xs text-gray-500 font-mono">No services detected on open ports.</span>
                )}
                <span className="ml-auto text-xs text-gray-500 font-mono">Duration: {result.duration_ms} ms</span>
              </div>
            </div>

            <div className="glass-card rounded-2xl p-5">
              <h3 className="text-sm font-semibold text-white mb-3">Issues & Security Indicators</h3>
              {result.issues.length === 0 ? (
                <p className="text-sm font-mono text-green-400 flex items-center gap-2">
                  <ShieldCheck size={14} />
                  No high-risk service exposure found in this scan.
                </p>
              ) : (
                <ul className="space-y-2">
                  {result.issues.map((issue) => (
                    <li key={issue} className="text-sm font-mono text-amber-300 flex items-start gap-2">
                      <AlertTriangle size={14} className="mt-0.5 shrink-0" />
                      <span>{issue}</span>
                    </li>
                  ))}
                </ul>
              )}
              <p className="mt-4 text-xs font-mono text-gray-500">{result.warning}</p>
            </div>

            <div className="glass-card rounded-2xl p-5">
              <h3 className="text-sm font-semibold text-white mb-3">Open Ports & Detected Services</h3>
              <div className="overflow-x-auto rounded-xl border border-white/10">
                <table className="w-full min-w-[860px] text-left table-auto">
                  <thead className="bg-white/5">
                    <tr>
                      <th className="px-3 py-2.5 text-xs text-gray-500 font-mono">Port</th>
                      <th className="px-3 py-2.5 text-xs text-gray-500 font-mono">Status</th>
                      <th className="px-3 py-2.5 text-xs text-gray-500 font-mono">Service</th>
                      <th className="px-3 py-2.5 text-xs text-gray-500 font-mono">Product/Version</th>
                      <th className="px-3 py-2.5 text-xs text-gray-500 font-mono">Banner</th>
                      <th className="px-3 py-2.5 text-xs text-gray-500 font-mono">Risk</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(result.open_port_details.length > 0 ? result.open_port_details : result.results).map((row) => (
                      <tr key={`${row.port}-${row.status}`} className="border-t border-white/10">
                        <td className="px-3 py-2.5 text-sm text-gray-200 font-mono">:{row.port}</td>
                        <td className="px-3 py-2.5">
                          <span className={`text-xs font-mono px-2 py-1 rounded border ${statusPillClass(row.status)}`}>
                            {row.status.toUpperCase()}
                          </span>
                        </td>
                        <td className="px-3 py-2.5 text-sm text-blue-300 font-mono">{row.service}</td>
                        <td className="px-3 py-2.5 text-sm text-gray-300 font-mono">
                          {row.product ? `${row.product}${row.version ? ` ${row.version}` : ''}` : '-'}
                        </td>
                        <td className="px-3 py-2.5 text-xs text-gray-500 font-mono break-all whitespace-normal align-top">
                          {row.banner || '-'}
                        </td>
                        <td className="px-3 py-2.5 text-xs font-mono">
                          {row.risky ? (
                            <span className="text-red-400">Risky</span>
                          ) : (
                            <span className="text-green-400">Safe</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}
      </div>
    </PageWrapper>
  )
}
