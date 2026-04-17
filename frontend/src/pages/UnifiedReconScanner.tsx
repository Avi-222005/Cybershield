import { FormEvent, useEffect, useMemo, useState } from 'react'
import {
  AlertTriangle,
  BarChart3,
  Download,
  Radar,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
} from 'lucide-react'
import PageWrapper from '../components/ui/PageWrapper'
import LoadingSpinner from '../components/ui/LoadingSpinner'
import CompactModuleStatusGrid from '../components/ui/unifiedRecon/CompactModuleStatusGrid'
import CollapsibleModuleCard from '../components/ui/unifiedRecon/CollapsibleModuleCard'
import { downloadUnifiedReconPdf, unifiedReconScan } from '../lib/api'
import type {
  UnifiedReconFinding,
  UnifiedReconResult,
  UnifiedReconScanMode,
} from '../types'

const MODE_OPTIONS: Array<{
  value: UnifiedReconScanMode
  label: string
  helper: string
}> = [
  { value: 'quick', label: 'Quick', helper: 'DNS, headers, SSL, and top-port exposure only' },
  { value: 'standard', label: 'Standard', helper: 'Balanced reconnaissance across all core intelligence modules' },
  { value: 'deep', label: 'Deep', helper: 'Maximum reconnaissance depth with expanded discovery and exposure context' },
]

const MODULES_BY_MODE: Record<UnifiedReconScanMode, string[]> = {
  quick: ['dns', 'headers', 'ssl', 'ports'],
  standard: ['dns', 'subdomains', 'headers', 'ssl', 'ports', 'tech', 'whois'],
  deep: ['dns', 'subdomains', 'headers', 'ssl', 'ports', 'tech', 'whois'],
}

const MODULE_LABELS: Record<string, string> = {
  dns: 'DNS Intelligence',
  subdomains: 'Subdomain Discovery',
  headers: 'HTTP Header Audit',
  ssl: 'SSL Certificate',
  ports: 'Port Exposure',
  tech: 'Technology Fingerprint',
  whois: 'WHOIS Intelligence',
}

function scoreTone(riskScore: number): string {
  if (riskScore <= 20) return '#22c55e'
  if (riskScore <= 40) return '#84cc16'
  if (riskScore <= 60) return '#f59e0b'
  if (riskScore <= 80) return '#f97316'
  return '#ef4444'
}

function gradePill(grade: UnifiedReconResult['grade']): string {
  if (grade === 'A+' || grade === 'A') return 'text-green-300 border-green-500/35 bg-green-500/10'
  if (grade === 'B' || grade === 'C') return 'text-amber-300 border-amber-500/35 bg-amber-500/10'
  return 'text-red-300 border-red-500/35 bg-red-500/10'
}

function riskPill(risk: UnifiedReconResult['risk_level']): string {
  if (risk === 'Excellent' || risk === 'Good') return 'text-green-300 border-green-500/35 bg-green-500/10'
  if (risk === 'Moderate') return 'text-amber-300 border-amber-500/35 bg-amber-500/10'
  if (risk === 'Risky') return 'text-orange-300 border-orange-500/35 bg-orange-500/10'
  return 'text-red-300 border-red-500/35 bg-red-500/10'
}

function severityPill(severity: UnifiedReconFinding['severity']): string {
  if (severity === 'Critical') return 'text-red-300 border-red-500/35 bg-red-500/10'
  if (severity === 'High') return 'text-orange-300 border-orange-500/35 bg-orange-500/10'
  if (severity === 'Medium') return 'text-amber-300 border-amber-500/35 bg-amber-500/10'
  return 'text-yellow-200 border-yellow-500/30 bg-yellow-500/10'
}

function DonutRiskScore({ score }: { score: number }) {
  const safe = Math.max(0, Math.min(100, score))
  const color = scoreTone(safe)
  const ring = `conic-gradient(${color} ${safe * 3.6}deg, rgba(255,255,255,0.12) ${safe * 3.6}deg)`

  return (
    <div className="flex items-center justify-center">
      <div className="relative h-36 w-36 rounded-full" style={{ background: ring, boxShadow: `0 0 26px ${color}33` }}>
        <div className="absolute inset-3 rounded-full bg-[#0b1424] border border-white/10 flex flex-col items-center justify-center">
          <div className="text-3xl font-bold font-mono" style={{ color }}>{safe}</div>
          <div className="text-[10px] text-gray-500 font-mono">RISK SCORE</div>
        </div>
      </div>
    </div>
  )
}

function RiskDistributionBar({
  critical,
  high,
  medium,
  low,
}: {
  critical: number
  high: number
  medium: number
  low: number
}) {
  const total = Math.max(1, critical + high + medium + low)
  const criticalPct = (critical / total) * 100
  const highPct = (high / total) * 100
  const mediumPct = (medium / total) * 100
  const lowPct = (low / total) * 100

  return (
    <div>
      <div className="text-xs text-gray-500 font-mono mb-2">Risk Distribution</div>
      <div className="h-3 rounded-full overflow-hidden border border-white/10 bg-white/5 flex">
        <div className="bg-red-500/80" style={{ width: `${criticalPct}%` }} />
        <div className="bg-orange-500/80" style={{ width: `${highPct}%` }} />
        <div className="bg-amber-500/80" style={{ width: `${mediumPct}%` }} />
        <div className="bg-yellow-400/80" style={{ width: `${lowPct}%` }} />
      </div>
      <div className="grid grid-cols-2 gap-2 mt-2 text-[11px] font-mono">
        <span className="text-red-300">Critical: {critical}</span>
        <span className="text-orange-300">High: {high}</span>
        <span className="text-amber-300">Medium: {medium}</span>
        <span className="text-yellow-200">Low: {low}</span>
      </div>
    </div>
  )
}

function KeyValueRow({ label, value }: { label: string; value: string | number | boolean | null | undefined }) {
  const text = value === null || value === undefined || value === '' ? 'N/A' : String(value)
  return (
    <div className="flex items-center justify-between gap-3 rounded-lg border border-white/10 bg-white/3 px-3 py-2">
      <span className="text-xs text-gray-500 font-mono">{label}</span>
      <span className="text-sm text-gray-200 font-mono text-right">{text}</span>
    </div>
  )
}

function TagList({ items, emptyText = 'None' }: { items: string[]; emptyText?: string }) {
  if (!items || items.length === 0) {
    return <div className="text-sm text-gray-500 font-mono">{emptyText}</div>
  }

  return (
    <div className="flex flex-wrap gap-1.5">
      {items.map((item) => (
        <span key={item} className="text-xs px-2 py-1 rounded border border-white/15 text-gray-300 bg-white/5 font-mono">
          {item}
        </span>
      ))}
    </div>
  )
}

export default function UnifiedReconScanner() {
  const [target, setTarget] = useState('')
  const [scanMode, setScanMode] = useState<UnifiedReconScanMode>('standard')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<UnifiedReconResult | null>(null)
  const [progressStep, setProgressStep] = useState(0)
  const [rawVisible, setRawVisible] = useState<Record<string, boolean>>({})

  const moduleOrder = useMemo(() => MODULES_BY_MODE[scanMode], [scanMode])

  useEffect(() => {
    if (!loading) return
    setProgressStep(0)
    const intervalId = window.setInterval(() => {
      setProgressStep((prev) => (prev + 1) % Math.max(1, moduleOrder.length))
    }, 700)

    return () => window.clearInterval(intervalId)
  }, [loading, moduleOrder.length])

  async function onSubmit(e: FormEvent) {
    e.preventDefault()
    const trimmed = target.trim()
    if (!trimmed) return

    setError(null)
    setLoading(true)
    setResult(null)
    setRawVisible({})

    try {
      const data = await unifiedReconScan(trimmed, scanMode)
      setResult(data)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Unified recon scan failed')
    } finally {
      setLoading(false)
    }
  }

  function toggleRaw(moduleKey: string) {
    setRawVisible((prev) => ({ ...prev, [moduleKey]: !prev[moduleKey] }))
  }

  function exportJson() {
    if (!result) return
    const payload = JSON.stringify(result, null, 2)
    const blob = new Blob([payload], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    const safeTarget = result.target.replace(/[^a-zA-Z0-9._-]+/g, '-')
    link.href = url
    link.download = `unified-recon-${safeTarget}.json`
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    URL.revokeObjectURL(url)
  }

  async function exportPdf() {
    if (!result) return
    try {
      const blob = await downloadUnifiedReconPdf({ result })
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      const safeTarget = result.target.replace(/[^a-zA-Z0-9._-]+/g, '-')
      link.href = url
      link.download = `unified-recon-${safeTarget}.pdf`
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
      URL.revokeObjectURL(url)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to export PDF')
    }
  }

  function renderRaw(moduleKey: string) {
    if (!result) return null
    const isVisible = !!rawVisible[moduleKey]

    return (
      <div className="mt-3">
        <button
          type="button"
          onClick={() => toggleRaw(moduleKey)}
          className="text-xs font-mono px-2.5 py-1.5 rounded border border-white/15 text-gray-300 hover:bg-white/5"
        >
          {isVisible ? 'Hide Raw Data' : 'View Raw Data'}
        </button>
        {isVisible && (
          <pre className="mt-2 bg-[#08101d] border border-white/10 rounded-lg p-3 text-xs text-gray-300 overflow-auto max-h-[320px]">
            {JSON.stringify(result.modules[moduleKey]?.data || {}, null, 2)}
          </pre>
        )}
      </div>
    )
  }

  function renderModuleCard(moduleKey: string) {
    if (!result) return null
    const moduleScore = result.module_scores[moduleKey]
    const moduleInfo = result.modules[moduleKey]
    const moduleView = result.module_views

    const badge = moduleScore ? (
      <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-white/15 text-gray-200 bg-white/5">
        {moduleScore.grade} | {moduleScore.risk_score}
      </span>
    ) : null

    if (moduleKey === 'dns') {
      const view = moduleView.dns
      return (
        <CollapsibleModuleCard key={moduleKey} title="DNS Intelligence" subtitle={`Completed in ${moduleInfo?.duration_ms || 0} ms`} badge={badge}>
          <div className="grid md:grid-cols-2 gap-2 mt-3">
            <KeyValueRow label="DNS Grade" value={view?.dns_grade} />
            <KeyValueRow label="DNSSEC" value={view?.dnssec_enabled ? 'Enabled' : 'Disabled'} />
            <KeyValueRow label="SPF" value={view?.spf_status} />
            <KeyValueRow label="DMARC" value={view?.dmarc_policy} />
            <KeyValueRow label="MX Count" value={view?.mx_count} />
            <KeyValueRow label="NS Count" value={view?.ns_count} />
          </div>

          <div className="mt-3">
            <div className="text-xs text-gray-500 font-mono mb-1.5">Key Issues</div>
            <TagList items={view?.key_issues || []} emptyText="No major DNS issues detected." />
          </div>

          <div className="mt-3">
            <div className="text-xs text-gray-500 font-mono mb-1.5">Recommendations</div>
            <TagList items={view?.recommendations || []} emptyText="No immediate DNS remediation required." />
          </div>

          {renderRaw(moduleKey)}
        </CollapsibleModuleCard>
      )
    }

    if (moduleKey === 'subdomains') {
      const view = moduleView.subdomains
      return (
        <CollapsibleModuleCard key={moduleKey} title="Subdomain Discovery" subtitle={`Completed in ${moduleInfo?.duration_ms || 0} ms`} badge={badge}>
          <div className="grid sm:grid-cols-3 gap-2 mt-3">
            <KeyValueRow label="Total Found" value={view?.total_found} />
            <KeyValueRow label="Live Hosts" value={view?.live_hosts} />
            <KeyValueRow label="High Risk Hosts" value={view?.high_risk_hosts} />
          </div>

          <div className="mt-3 overflow-x-auto rounded-lg border border-white/10">
            <table className="w-full min-w-[640px] text-sm">
              <thead className="bg-white/5 text-xs text-gray-500 font-mono">
                <tr>
                  <th className="px-3 py-2 text-left">Host</th>
                  <th className="px-3 py-2 text-left">Status</th>
                  <th className="px-3 py-2 text-left">Risk</th>
                  <th className="px-3 py-2 text-left">Title</th>
                </tr>
              </thead>
              <tbody>
                {(view?.top_risky_subdomains || []).map((row) => (
                  <tr key={row.host} className="border-t border-white/10">
                    <td className="px-3 py-2 font-mono text-gray-200">{row.host}</td>
                    <td className="px-3 py-2 text-gray-300 font-mono">{row.status}</td>
                    <td className="px-3 py-2 text-gray-300 font-mono">{row.risk}</td>
                    <td className="px-3 py-2 text-gray-300">{row.title || '-'}</td>
                  </tr>
                ))}
                {(!view?.top_risky_subdomains || view.top_risky_subdomains.length === 0) && (
                  <tr>
                    <td colSpan={4} className="px-3 py-3 text-gray-500 font-mono">No risky subdomain rows available.</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          {renderRaw(moduleKey)}
        </CollapsibleModuleCard>
      )
    }

    if (moduleKey === 'headers') {
      const view = moduleView.headers
      return (
        <CollapsibleModuleCard key={moduleKey} title="HTTP Header Audit" subtitle={`Completed in ${moduleInfo?.duration_ms || 0} ms`} badge={badge}>
          <div className="grid md:grid-cols-2 gap-2 mt-3">
            <KeyValueRow label="Header Grade" value={view?.header_grade} />
            <KeyValueRow label="HSTS" value={view?.hsts_status} />
            <KeyValueRow label="Cookie Security" value={view?.cookie_security} />
            <KeyValueRow label="Information Leakage" value={(view?.information_leakage || []).length} />
          </div>

          <div className="mt-3">
            <div className="text-xs text-gray-500 font-mono mb-1.5">Missing Security Headers</div>
            <TagList items={view?.missing_security_headers || []} emptyText="No critical header gaps." />
          </div>

          {renderRaw(moduleKey)}
        </CollapsibleModuleCard>
      )
    }

    if (moduleKey === 'ssl') {
      const view = moduleView.ssl
      return (
        <CollapsibleModuleCard key={moduleKey} title="SSL Certificate" subtitle={`Completed in ${moduleInfo?.duration_ms || 0} ms`} badge={badge}>
          <div className="grid md:grid-cols-2 gap-2 mt-3">
            <KeyValueRow label="Validity" value={view?.valid ? 'Valid' : 'Invalid'} />
            <KeyValueRow label="Issuer" value={view?.issuer} />
            <KeyValueRow label="Expires In" value={view?.expires_in_days !== undefined ? `${view?.expires_in_days} days` : 'N/A'} />
            <KeyValueRow label="Cipher Strength" value={view?.cipher_strength || 'Unknown'} />
          </div>
          {renderRaw(moduleKey)}
        </CollapsibleModuleCard>
      )
    }

    if (moduleKey === 'ports') {
      const view = moduleView.ports
      return (
        <CollapsibleModuleCard key={moduleKey} title="Port Exposure" subtitle={`Completed in ${moduleInfo?.duration_ms || 0} ms`} badge={badge}>
          <div className="grid sm:grid-cols-2 gap-2 mt-3">
            <KeyValueRow label="Open Ports" value={view?.open_ports_count} />
            <KeyValueRow label="Risky Ports" value={view?.risky_ports_count} />
          </div>

          <div className="mt-3 overflow-x-auto rounded-lg border border-white/10">
            <table className="w-full min-w-[620px] text-sm">
              <thead className="bg-white/5 text-xs text-gray-500 font-mono">
                <tr>
                  <th className="px-3 py-2 text-left">Port</th>
                  <th className="px-3 py-2 text-left">Service</th>
                  <th className="px-3 py-2 text-left">Risk</th>
                  <th className="px-3 py-2 text-left">Notes</th>
                </tr>
              </thead>
              <tbody>
                {(view?.services_table || []).slice(0, 20).map((row) => (
                  <tr key={`${row.port}-${row.service}`} className="border-t border-white/10">
                    <td className="px-3 py-2 text-gray-200 font-mono">{row.port}</td>
                    <td className="px-3 py-2 text-gray-300 font-mono">{row.service}</td>
                    <td className="px-3 py-2 text-gray-300 font-mono">{row.risk}</td>
                    <td className="px-3 py-2 text-gray-300">{row.notes}</td>
                  </tr>
                ))}
                {(!view?.services_table || view.services_table.length === 0) && (
                  <tr>
                    <td colSpan={4} className="px-3 py-3 text-gray-500 font-mono">No open service rows available.</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          {renderRaw(moduleKey)}
        </CollapsibleModuleCard>
      )
    }

    if (moduleKey === 'tech') {
      const view = moduleView.tech
      return (
        <CollapsibleModuleCard key={moduleKey} title="Technology Fingerprint" subtitle={`Completed in ${moduleInfo?.duration_ms || 0} ms`} badge={badge}>
          <div className="grid md:grid-cols-2 gap-3 mt-3">
            <div>
              <div className="text-xs text-gray-500 font-mono mb-1.5">Server</div>
              <TagList items={view?.server || []} emptyText="Unknown" />
            </div>
            <div>
              <div className="text-xs text-gray-500 font-mono mb-1.5">Frameworks</div>
              <TagList items={view?.frameworks || []} emptyText="Unknown" />
            </div>
            <div>
              <div className="text-xs text-gray-500 font-mono mb-1.5">CMS</div>
              <TagList items={view?.cms || []} emptyText="Unknown" />
            </div>
            <div>
              <div className="text-xs text-gray-500 font-mono mb-1.5">CDN</div>
              <TagList items={view?.cdn || []} emptyText="Unknown" />
            </div>
            <div>
              <div className="text-xs text-gray-500 font-mono mb-1.5">Language</div>
              <TagList items={view?.language || []} emptyText="Unknown" />
            </div>
          </div>

          {renderRaw(moduleKey)}
        </CollapsibleModuleCard>
      )
    }

    if (moduleKey === 'whois') {
      const view = moduleView.whois
      return (
        <CollapsibleModuleCard key={moduleKey} title="WHOIS Intelligence" subtitle={`Completed in ${moduleInfo?.duration_ms || 0} ms`} badge={badge}>
          <div className="grid md:grid-cols-2 gap-2 mt-3">
            <KeyValueRow label="Registrar" value={view?.registrar} />
            <KeyValueRow label="Domain Age" value={view?.domain_age_days !== null && view?.domain_age_days !== undefined ? `${view.domain_age_days} days` : 'N/A'} />
            <KeyValueRow label="Expiry Date" value={view?.expiry_date} />
            <KeyValueRow label="Registrant Country" value={view?.registrant_country} />
          </div>
          {renderRaw(moduleKey)}
        </CollapsibleModuleCard>
      )
    }

    return null
  }

  return (
    <PageWrapper>
      <div className="max-w-7xl mx-auto px-4 sm:px-6 pt-28 pb-20">
        <div className="mb-7">
          <div className="flex items-center gap-2.5 mb-2">
            <div className="p-2 rounded-lg bg-[#0d6efd]/10 border border-[#0d6efd]/20">
              <Radar size={18} className="text-[#0d6efd]" />
            </div>
            <h1 className="text-2xl font-bold text-white">Unified Recon Scanner</h1>
          </div>
          <p className="text-gray-500 text-sm ml-10">
            Enterprise-style consolidated external intelligence across DNS, exposure, web controls, and infrastructure signals.
          </p>
        </div>

        <div className="glass-card rounded-2xl p-4 mb-5 border border-amber-500/25 bg-amber-500/5">
          <p className="text-amber-300 text-sm font-mono flex items-start gap-2">
            <ShieldAlert size={15} className="mt-0.5 shrink-0" />
            Scan only assets that you own or are explicitly authorized to assess.
          </p>
        </div>

        <form onSubmit={onSubmit} className="glass-card rounded-2xl p-5 mb-6">
          <div className="grid grid-cols-1 lg:grid-cols-5 gap-3 mb-3">
            <div className="lg:col-span-3">
              <label className="block text-xs font-mono text-gray-400 mb-2 uppercase tracking-wider">Target</label>
              <input
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="example.com, https://example.com, or 8.8.8.8"
                className="cyber-input w-full px-4 py-3 rounded-xl text-sm font-mono"
                disabled={loading}
              />
            </div>

            <div>
              <label className="block text-xs font-mono text-gray-400 mb-2 uppercase tracking-wider">Scan Mode</label>
              <select
                value={scanMode}
                onChange={(e) => setScanMode(e.target.value as UnifiedReconScanMode)}
                className="cyber-input w-full px-4 py-3 rounded-xl text-sm font-mono"
                disabled={loading}
              >
                {MODE_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value}>{option.label}</option>
                ))}
              </select>
            </div>

            <div className="flex items-end">
              <button
                type="submit"
                disabled={loading || !target.trim()}
                className="w-full px-5 py-3 bg-[#0d6efd] hover:bg-[#0b5ed7] disabled:opacity-50 disabled:cursor-not-allowed !text-white font-semibold rounded-xl text-sm"
              >
                {loading ? 'Scanning...' : 'Start Unified Scan'}
              </button>
            </div>
          </div>

          <p className="text-xs text-gray-500 font-mono">
            {MODE_OPTIONS.find((x) => x.value === scanMode)?.helper}
          </p>
        </form>

        {loading && (
          <div className="glass-card rounded-2xl mb-6">
            <LoadingSpinner label="Running weighted reconnaissance and normalizing intelligence outputs..." />
          </div>
        )}

        {error && (
          <div className="glass-card rounded-2xl p-5 border border-red-500/25 bg-red-500/5 text-red-400 text-sm font-mono mb-6">
            {error}
          </div>
        )}

        {result && (
          <div className="space-y-5">
            <div className="glass-card rounded-2xl p-5">
              <div className="flex flex-wrap items-start justify-between gap-3 mb-3">
                <div>
                  <h2 className="text-lg font-semibold text-white">Executive Summary</h2>
                  <p className="text-xs text-gray-500 font-mono mt-1">
                    Target: {result.target} | Mode: {result.scan_mode.toUpperCase()} | Duration: {result.scan_duration_ms} ms
                    {result.cached ? ' | CACHE HIT' : ''}
                  </p>
                </div>

                <div className="flex gap-2">
                  <button
                    type="button"
                    onClick={exportJson}
                    className="flex items-center gap-2 text-xs font-mono px-3 py-2 rounded-lg border border-white/15 text-gray-200 hover:bg-white/5"
                  >
                    <Download size={13} /> Export JSON
                  </button>
                  <button
                    type="button"
                    onClick={exportPdf}
                    className="flex items-center gap-2 text-xs font-mono px-3 py-2 rounded-lg border border-[#0d6efd]/30 text-[#6ea8fe] hover:bg-[#0d6efd]/10"
                  >
                    <Download size={13} /> Export PDF
                  </button>
                </div>
              </div>

              <p className="text-sm text-gray-300">{result.summary}</p>
            </div>

            <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
              <div className="glass-card rounded-2xl p-5">
                <DonutRiskScore score={result.risk_score} />
                <div className="mt-4 flex items-center justify-center gap-2 flex-wrap">
                  <span className={`text-xs font-mono px-2.5 py-1 rounded border ${gradePill(result.grade)}`}>
                    Grade {result.grade}
                  </span>
                  <span className={`text-xs font-mono px-2.5 py-1 rounded border ${riskPill(result.risk_level)}`}>
                    {result.risk_level}
                  </span>
                </div>
              </div>

              <div className="glass-card rounded-2xl p-5 xl:col-span-2">
                <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-2 mb-4">
                  <KeyValueRow label="Subdomains" value={result.highlights.subdomains_found} />
                  <KeyValueRow label="Open Ports" value={result.highlights.open_ports.length} />
                  <KeyValueRow label="DNS Grade" value={result.highlights.dns_grade} />
                  <KeyValueRow label="Header Grade" value={result.highlights.header_grade} />
                </div>

                <RiskDistributionBar
                  critical={result.risk_distribution.critical}
                  high={result.risk_distribution.high}
                  medium={result.risk_distribution.medium}
                  low={result.risk_distribution.low}
                />

                <div className="mt-4">
                  <div className="text-xs text-gray-500 font-mono mb-2">Module Grades</div>
                  <div className="flex flex-wrap gap-1.5">
                    {moduleOrder.map((moduleKey) => {
                      const score = result.module_scores[moduleKey]
                      if (!score) return null
                      return (
                        <span
                          key={moduleKey}
                          className="text-xs px-2 py-1 rounded border border-white/15 text-gray-200 bg-white/5 font-mono"
                        >
                          {MODULE_LABELS[moduleKey]}: {score.grade}
                        </span>
                      )
                    })}
                  </div>
                </div>
              </div>
            </div>

            <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
              <div className="glass-card rounded-2xl p-5">
                <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
                  <AlertTriangle size={14} className="text-amber-400" /> Top Findings
                </h3>

                {result.findings.length === 0 ? (
                  <p className="text-sm text-green-400 font-mono">No significant findings in this scan.</p>
                ) : (
                  <div className="space-y-2.5">
                    {result.findings.slice(0, 5).map((finding) => (
                      <div key={`${finding.module}-${finding.title}`} className="rounded-lg border border-white/10 bg-white/3 px-3 py-2.5">
                        <div className="flex items-start justify-between gap-2">
                          <div className="text-sm text-gray-200">{finding.title}</div>
                          <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${severityPill(finding.severity)}`}>
                            {finding.severity}
                          </span>
                        </div>
                        {finding.detail && <div className="mt-1 text-xs text-gray-500 font-mono">{finding.detail}</div>}
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div className="glass-card rounded-2xl p-5">
                <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
                  <Sparkles size={14} className="text-[#6ea8fe]" /> Priority Recommendations
                </h3>
                {result.recommendations.length === 0 ? (
                  <p className="text-sm text-green-400 font-mono">No immediate action required.</p>
                ) : (
                  <ul className="space-y-2">
                    {result.recommendations.slice(0, 8).map((recommendation) => (
                      <li key={recommendation} className="text-sm text-gray-300 font-mono flex items-start gap-2">
                        <ShieldCheck size={13} className="mt-0.5 shrink-0 text-[#6ea8fe]" />
                        <span>{recommendation}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </div>

            <div className="glass-card rounded-2xl p-5">
              <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
                <BarChart3 size={14} className="text-[#6ea8fe]" /> Module Status
              </h3>
              <CompactModuleStatusGrid
                moduleOrder={moduleOrder}
                moduleLabels={MODULE_LABELS}
                modules={result.modules}
                loading={loading}
                progressStep={progressStep}
              />
            </div>

            <div className="glass-card rounded-2xl p-5">
              <h3 className="text-sm font-semibold text-white mb-3">Detailed Module Breakdown</h3>
              <div className="space-y-3">
                {moduleOrder.map((moduleKey) => renderModuleCard(moduleKey))}
              </div>
            </div>
          </div>
        )}
      </div>
    </PageWrapper>
  )
}
