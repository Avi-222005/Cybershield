import { FormEvent, useEffect, useMemo, useRef, useState } from 'react'
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
import {
  downloadUnifiedReconPdf,
  getUnifiedReconScanStatus,
  startUnifiedReconScan,
} from '../lib/api'
import type {
  UnifiedReconFinding,
  UnifiedReconModuleResult,
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

function tableStatusPill(status: string): string {
  const normalized = status.toLowerCase()
  if (normalized === 'present' || normalized === 'live' || normalized === 'open' || normalized === 'valid') {
    return 'text-green-300 border-green-500/35 bg-green-500/10'
  }
  if (normalized === 'weak' || normalized === 'redirect' || normalized === 'timeout' || normalized === 'filtered') {
    return 'text-amber-300 border-amber-500/35 bg-amber-500/10'
  }
  if (normalized === 'missing' || normalized === 'dead' || normalized === 'invalid' || normalized === 'closed' || normalized === 'failed') {
    return 'text-red-300 border-red-500/35 bg-red-500/10'
  }
  return 'text-gray-300 border-white/20 bg-white/5'
}

function riskLevelPill(risk: string): string {
  const normalized = risk.toUpperCase()
  if (normalized === 'HIGH') return 'text-red-300 border-red-500/35 bg-red-500/10'
  if (normalized === 'MEDIUM') return 'text-amber-300 border-amber-500/35 bg-amber-500/10'
  if (normalized === 'LOW') return 'text-green-300 border-green-500/35 bg-green-500/10'
  return 'text-gray-300 border-white/20 bg-white/5'
}

export default function UnifiedReconScanner() {
  const [target, setTarget] = useState('')
  const [scanMode, setScanMode] = useState<UnifiedReconScanMode>('standard')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<UnifiedReconResult | null>(null)
  const [scanJobId, setScanJobId] = useState<string | null>(null)
  const [liveModuleOrder, setLiveModuleOrder] = useState<string[]>(MODULES_BY_MODE.standard)
  const [liveModules, setLiveModules] = useState<Record<string, UnifiedReconModuleResult>>({})
  const pollingInFlight = useRef(false)

  const moduleOrder = useMemo(() => MODULES_BY_MODE[scanMode], [scanMode])
  const resultModuleOrder = useMemo(
    () => (result ? MODULES_BY_MODE[result.scan_mode] : moduleOrder),
    [result, moduleOrder],
  )

  const scanProgress = useMemo(() => {
    const order = liveModuleOrder.length > 0 ? liveModuleOrder : moduleOrder
    const total = order.length
    if (!loading || total === 0) {
      return {
        total,
        done: 0,
        running: 0,
        pending: total,
        runningLabel: null as string | null,
      }
    }

    let done = 0
    let running = 0
    let pending = 0
    let runningLabel: string | null = null

    for (const key of order) {
      const entry = liveModules[key]
      const state = entry?.state || (entry ? (entry.ok ? 'ok' : 'error') : 'pending')

      if (state === 'running') {
        running += 1
        if (!runningLabel) {
          runningLabel = MODULE_LABELS[key] || key
        }
      } else if (state === 'ok' || state === 'error') {
        done += 1
      } else {
        pending += 1
      }
    }

    return {
      total,
      done,
      running,
      pending,
      runningLabel,
    }
  }, [loading, liveModuleOrder, liveModules, moduleOrder])

  useEffect(() => {
    if (!loading || !scanJobId) {
      pollingInFlight.current = false
      return
    }

    let cancelled = false

    const pollStatus = async () => {
      if (cancelled || pollingInFlight.current) return
      pollingInFlight.current = true
      try {
        const status = await getUnifiedReconScanStatus(scanJobId)
        if (cancelled) return

        if (Array.isArray(status.module_order) && status.module_order.length > 0) {
          setLiveModuleOrder(status.module_order)
        }
        if (status.modules) {
          setLiveModules(status.modules)
        }

        if (status.status === 'completed') {
          if (status.result) {
            setResult(status.result)
            setError(null)
          } else {
            setError('Scan completed without a result payload.')
          }
          setLoading(false)
          setScanJobId(null)
        } else if (status.status === 'failed') {
          setError(status.error || 'Unified recon scan failed')
          setLoading(false)
          setScanJobId(null)
        }
      } catch (err: unknown) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : 'Failed to fetch scan status')
          setLoading(false)
          setScanJobId(null)
        }
      } finally {
        pollingInFlight.current = false
      }
    }

    void pollStatus()
    const intervalId = window.setInterval(() => {
      void pollStatus()
    }, 1000)

    return () => {
      cancelled = true
      window.clearInterval(intervalId)
      pollingInFlight.current = false
    }
  }, [loading, scanJobId])

  async function onSubmit(e: FormEvent) {
    e.preventDefault()
    const trimmed = target.trim()
    if (!trimmed) return

    setError(null)
    setLoading(true)
    setResult(null)
    setScanJobId(null)
    setLiveModules({})
    setLiveModuleOrder(MODULES_BY_MODE[scanMode])

    try {
      const startPayload = await startUnifiedReconScan(trimmed, scanMode)

      if (Array.isArray(startPayload.module_order) && startPayload.module_order.length > 0) {
        setLiveModuleOrder(startPayload.module_order)
      }
      if (startPayload.modules) {
        setLiveModules(startPayload.modules)
      }

      if (startPayload.status === 'completed') {
        if (startPayload.result) {
          setResult(startPayload.result)
        } else {
          setError('Scan completed without a result payload.')
        }
        setLoading(false)
        return
      }

      if (startPayload.status === 'failed') {
        setError(startPayload.error || 'Unified recon scan failed')
        setLoading(false)
        return
      }

      if (!startPayload.job_id) {
        throw new Error('Scan job did not return a valid job id.')
      }

      setScanJobId(startPayload.job_id)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Unified recon scan failed')
      setLoading(false)
    }
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

  function renderModuleCard(moduleKey: string) {
    if (!result) return null
    const moduleScore = result.module_scores[moduleKey]
    const moduleInfo = result.modules[moduleKey]
    const moduleView = result.module_views
    const moduleData = (moduleInfo?.data || {}) as Record<string, unknown>
    const moduleError = moduleInfo?.error

    const badge = moduleScore ? (
      <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-white/15 text-gray-200 bg-white/5">
        {moduleScore.grade} | {moduleScore.risk_score}
      </span>
    ) : null

    if (moduleKey === 'dns') {
      const view = moduleView.dns
      const records = Object.entries((moduleData.records as Record<string, string[]>) || {})
      const hasRecords = records.length > 0

      return (
        <CollapsibleModuleCard key={moduleKey} title="DNS Intelligence" subtitle={`Completed in ${moduleInfo?.duration_ms || 0} ms`} badge={badge}>
          {moduleError && (
            <div className="mt-3 rounded-lg border border-red-500/25 bg-red-500/5 px-3 py-2 text-xs text-red-300 font-mono">
              {moduleError}
            </div>
          )}

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

          <div className="mt-4">
            <div className="text-xs text-gray-500 font-mono mb-2">DNS Records</div>
            {hasRecords ? (
              <div className="overflow-x-auto rounded-lg border border-white/10">
                <table className="w-full min-w-[760px] text-sm">
                  <thead className="bg-white/5 text-xs text-gray-500 font-mono">
                    <tr>
                      <th className="px-3 py-2 text-left">Type</th>
                      <th className="px-3 py-2 text-left">Values</th>
                    </tr>
                  </thead>
                  <tbody>
                    {records.map(([type, values]) => (
                      <tr key={type} className="border-t border-white/10 align-top">
                        <td className="px-3 py-2 text-gray-200 font-mono whitespace-nowrap">{type}</td>
                        <td className="px-3 py-2">
                          {Array.isArray(values) && values.length > 0 ? (
                            <div className="space-y-1">
                              {values.slice(0, 8).map((value) => (
                                <div key={`${type}-${value}`} className="text-gray-300 font-mono break-all text-xs sm:text-sm">
                                  {value}
                                </div>
                              ))}
                              {values.length > 8 && (
                                <div className="text-[11px] text-gray-500 font-mono">+{values.length - 8} more</div>
                              )}
                            </div>
                          ) : (
                            <span className="text-gray-500 font-mono">No records</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="text-sm text-gray-500 font-mono">No DNS record table available.</div>
            )}
          </div>
        </CollapsibleModuleCard>
      )
    }

    if (moduleKey === 'subdomains') {
      const view = moduleView.subdomains
      const rows = ((moduleData.subdomains as Array<Record<string, unknown>>) || []).slice(0, 120)
      const historicalRows = ((moduleData.historical_candidates as Array<Record<string, unknown>>) || []).slice(0, 40)

      return (
        <CollapsibleModuleCard key={moduleKey} title="Subdomain Discovery" subtitle={`Completed in ${moduleInfo?.duration_ms || 0} ms`} badge={badge}>
          {moduleError && (
            <div className="mt-3 rounded-lg border border-red-500/25 bg-red-500/5 px-3 py-2 text-xs text-red-300 font-mono">
              {moduleError}
            </div>
          )}

          <div className="grid sm:grid-cols-3 gap-2 mt-3">
            <KeyValueRow label="Total Found" value={view?.total_found} />
            <KeyValueRow label="Live Hosts" value={view?.live_hosts} />
            <KeyValueRow label="High Risk Hosts" value={view?.high_risk_hosts} />
          </div>

          <div className="mt-4 overflow-x-auto rounded-lg border border-white/10">
            <table className="w-full min-w-[980px] text-sm">
              <thead className="bg-white/5 text-xs text-gray-500 font-mono">
                <tr>
                  <th className="px-3 py-2 text-left">Host</th>
                  <th className="px-3 py-2 text-left">IP</th>
                  <th className="px-3 py-2 text-left">Status</th>
                  <th className="px-3 py-2 text-left">Code</th>
                  <th className="px-3 py-2 text-left">Risk</th>
                  <th className="px-3 py-2 text-left">Title</th>
                  <th className="px-3 py-2 text-left">Sources</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => {
                  const host = String(row.host || '-')
                  const status = String(row.status || '-')
                  const risk = String(row.risk || '-')
                  const code = row.http_code === null || row.http_code === undefined ? '-' : String(row.http_code)
                  const sourceList = Array.isArray(row.sources) ? row.sources.map((s) => String(s)).join(', ') : '-'

                  return (
                    <tr key={host} className="border-t border-white/10">
                      <td className="px-3 py-2 font-mono text-gray-200">{host}</td>
                      <td className="px-3 py-2 text-gray-300 font-mono">{String(row.ip || '-')}</td>
                      <td className="px-3 py-2">
                        <span className={`text-[11px] px-2 py-0.5 rounded border font-mono ${tableStatusPill(status)}`}>
                          {status}
                        </span>
                      </td>
                      <td className="px-3 py-2 text-gray-300 font-mono">{code}</td>
                      <td className="px-3 py-2">
                        <span className={`text-[11px] px-2 py-0.5 rounded border font-mono ${riskLevelPill(risk)}`}>
                          {risk}
                        </span>
                      </td>
                      <td className="px-3 py-2 text-gray-300 max-w-[280px] truncate" title={String(row.title || '-')}>{String(row.title || '-')}</td>
                      <td className="px-3 py-2 text-gray-400 text-xs font-mono max-w-[220px] truncate" title={sourceList}>{sourceList}</td>
                    </tr>
                  )
                })}
                {rows.length === 0 && (
                  <tr>
                    <td colSpan={7} className="px-3 py-3 text-gray-500 font-mono">No subdomain rows available.</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          {historicalRows.length > 0 && (
            <div className="mt-4">
              <div className="text-xs text-gray-500 font-mono mb-2">Historical Unresolved Candidates</div>
              <div className="overflow-x-auto rounded-lg border border-white/10">
                <table className="w-full min-w-[760px] text-sm">
                  <thead className="bg-white/5 text-xs text-gray-500 font-mono">
                    <tr>
                      <th className="px-3 py-2 text-left">Host</th>
                      <th className="px-3 py-2 text-left">Risk</th>
                      <th className="px-3 py-2 text-left">Reason</th>
                      <th className="px-3 py-2 text-left">Sources</th>
                    </tr>
                  </thead>
                  <tbody>
                    {historicalRows.map((row) => {
                      const host = String(row.host || '-')
                      const risk = String(row.risk || '-')
                      const sourceList = Array.isArray(row.sources) ? row.sources.map((s) => String(s)).join(', ') : '-'
                      return (
                        <tr key={`historical-${host}`} className="border-t border-white/10">
                          <td className="px-3 py-2 text-gray-200 font-mono">{host}</td>
                          <td className="px-3 py-2">
                            <span className={`text-[11px] px-2 py-0.5 rounded border font-mono ${riskLevelPill(risk)}`}>
                              {risk}
                            </span>
                          </td>
                          <td className="px-3 py-2 text-gray-300">{String(row.reason || '-')}</td>
                          <td className="px-3 py-2 text-gray-400 text-xs font-mono">{sourceList}</td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </CollapsibleModuleCard>
      )
    }

    if (moduleKey === 'headers') {
      const view = moduleView.headers
      const securityRows = ((moduleData.security_headers as Array<Record<string, string>>) || []).slice(0, 40)
      const cookieRows = ((moduleData.cookies as Array<Record<string, unknown>>) || []).slice(0, 60)

      return (
        <CollapsibleModuleCard key={moduleKey} title="HTTP Header Audit" subtitle={`Completed in ${moduleInfo?.duration_ms || 0} ms`} badge={badge}>
          {moduleError && (
            <div className="mt-3 rounded-lg border border-red-500/25 bg-red-500/5 px-3 py-2 text-xs text-red-300 font-mono">
              {moduleError}
            </div>
          )}

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

          <div className="mt-4">
            <div className="text-xs text-gray-500 font-mono mb-2">Security Header Matrix</div>
            <div className="overflow-x-auto rounded-lg border border-white/10">
              <table className="w-full min-w-[760px] text-sm">
                <thead className="bg-white/5 text-xs text-gray-500 font-mono">
                  <tr>
                    <th className="px-3 py-2 text-left">Header</th>
                    <th className="px-3 py-2 text-left">Status</th>
                    <th className="px-3 py-2 text-left">Notes</th>
                  </tr>
                </thead>
                <tbody>
                  {securityRows.map((row) => {
                    const header = String(row.header || '-')
                    const status = String(row.status || '-')
                    return (
                      <tr key={header} className="border-t border-white/10">
                        <td className="px-3 py-2 text-gray-200 font-mono">{header}</td>
                        <td className="px-3 py-2">
                          <span className={`text-[11px] px-2 py-0.5 rounded border font-mono ${tableStatusPill(status)}`}>
                            {status}
                          </span>
                        </td>
                        <td className="px-3 py-2 text-gray-300">{String(row.notes || '-')}</td>
                      </tr>
                    )
                  })}
                  {securityRows.length === 0 && (
                    <tr>
                      <td colSpan={3} className="px-3 py-3 text-gray-500 font-mono">No security header rows available.</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          <div className="mt-4">
            <div className="text-xs text-gray-500 font-mono mb-2">Cookie Security Table</div>
            <div className="overflow-x-auto rounded-lg border border-white/10">
              <table className="w-full min-w-[920px] text-sm">
                <thead className="bg-white/5 text-xs text-gray-500 font-mono">
                  <tr>
                    <th className="px-3 py-2 text-left">Cookie</th>
                    <th className="px-3 py-2 text-left">HttpOnly</th>
                    <th className="px-3 py-2 text-left">Secure</th>
                    <th className="px-3 py-2 text-left">SameSite</th>
                    <th className="px-3 py-2 text-left">Risk</th>
                  </tr>
                </thead>
                <tbody>
                  {cookieRows.map((row) => {
                    const name = String(row.cookie_name || '-')
                    const risk = String(row.risk || 'None')
                    return (
                      <tr key={name} className="border-t border-white/10">
                        <td className="px-3 py-2 text-gray-200 font-mono">{name}</td>
                        <td className="px-3 py-2 text-gray-300 font-mono">{row.httponly ? 'Yes' : 'No'}</td>
                        <td className="px-3 py-2 text-gray-300 font-mono">{row.secure ? 'Yes' : 'No'}</td>
                        <td className="px-3 py-2 text-gray-300 font-mono">{String(row.samesite || '-')}</td>
                        <td className="px-3 py-2 text-gray-300">{risk}</td>
                      </tr>
                    )
                  })}
                  {cookieRows.length === 0 && (
                    <tr>
                      <td colSpan={5} className="px-3 py-3 text-gray-500 font-mono">No cookie security rows available.</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </CollapsibleModuleCard>
      )
    }

    if (moduleKey === 'ssl') {
      const view = moduleView.ssl
      const sslStatus = String(moduleData.status || (view?.valid ? 'Valid' : 'Invalid'))

      return (
        <CollapsibleModuleCard key={moduleKey} title="SSL Certificate" subtitle={`Completed in ${moduleInfo?.duration_ms || 0} ms`} badge={badge}>
          {moduleError && (
            <div className="mt-3 rounded-lg border border-red-500/25 bg-red-500/5 px-3 py-2 text-xs text-red-300 font-mono">
              {moduleError}
            </div>
          )}

          <div className="grid md:grid-cols-2 gap-2 mt-3">
            <KeyValueRow label="Validity" value={view?.valid ? 'Valid' : 'Invalid'} />
            <KeyValueRow label="Issuer" value={view?.issuer} />
            <KeyValueRow label="Expires In" value={view?.expires_in_days !== undefined ? `${view?.expires_in_days} days` : 'N/A'} />
            <KeyValueRow label="Cipher Strength" value={view?.cipher_strength || 'Unknown'} />
            <KeyValueRow label="Subject" value={moduleData.subject as string} />
            <KeyValueRow label="Valid From" value={moduleData.valid_from as string} />
            <KeyValueRow label="Valid Until" value={moduleData.valid_until as string} />
            <KeyValueRow label="Status" value={sslStatus} />
          </div>

          {!moduleInfo?.ok && (
            <div className="mt-3 text-sm text-red-300 font-mono">
              {String(moduleData.message || 'SSL module failed to fetch certificate details.')}
            </div>
          )}
        </CollapsibleModuleCard>
      )
    }

    if (moduleKey === 'ports') {
      const view = moduleView.ports
      const rows = ((moduleData.open_port_details as Array<Record<string, unknown>>) || [])
      const fallbackRows = ((moduleData.results as Array<Record<string, unknown>>) || []).filter((row) => String(row.status || '').toLowerCase() === 'open')
      const visibleRows = (rows.length > 0 ? rows : fallbackRows).slice(0, 80)

      return (
        <CollapsibleModuleCard key={moduleKey} title="Port Exposure" subtitle={`Completed in ${moduleInfo?.duration_ms || 0} ms`} badge={badge}>
          {moduleError && (
            <div className="mt-3 rounded-lg border border-red-500/25 bg-red-500/5 px-3 py-2 text-xs text-red-300 font-mono">
              {moduleError}
            </div>
          )}

          <div className="grid sm:grid-cols-2 gap-2 mt-3">
            <KeyValueRow label="Open Ports" value={view?.open_ports_count} />
            <KeyValueRow label="Risky Ports" value={view?.risky_ports_count} />
          </div>

          <div className="mt-3 overflow-x-auto rounded-lg border border-white/10">
            <table className="w-full min-w-[920px] text-sm">
              <thead className="bg-white/5 text-xs text-gray-500 font-mono">
                <tr>
                  <th className="px-3 py-2 text-left">Port</th>
                  <th className="px-3 py-2 text-left">Status</th>
                  <th className="px-3 py-2 text-left">Service</th>
                  <th className="px-3 py-2 text-left">Product/Version</th>
                  <th className="px-3 py-2 text-left">Risk</th>
                  <th className="px-3 py-2 text-left">Banner / Notes</th>
                </tr>
              </thead>
              <tbody>
                {visibleRows.map((row) => {
                  const port = String(row.port || '-')
                  const status = String(row.status || 'open')
                  const risk = row.risky ? 'HIGH' : 'LOW'
                  const productVersion = `${String(row.product || '')}${row.version ? ` ${String(row.version)}` : ''}`.trim() || '-'
                  const notes = String(row.issue || row.notes || row.banner || '-')
                  return (
                    <tr key={`${port}-${String(row.service || 'unknown')}`} className="border-t border-white/10">
                      <td className="px-3 py-2 text-gray-200 font-mono">{port}</td>
                      <td className="px-3 py-2">
                        <span className={`text-[11px] px-2 py-0.5 rounded border font-mono ${tableStatusPill(status)}`}>
                          {status.toUpperCase()}
                        </span>
                      </td>
                      <td className="px-3 py-2 text-gray-300 font-mono">{String(row.service || 'Unknown')}</td>
                      <td className="px-3 py-2 text-gray-300 font-mono">{productVersion}</td>
                      <td className="px-3 py-2">
                        <span className={`text-[11px] px-2 py-0.5 rounded border font-mono ${riskLevelPill(risk)}`}>{risk}</span>
                      </td>
                      <td className="px-3 py-2 text-gray-300 max-w-[320px] truncate" title={notes}>{notes}</td>
                    </tr>
                  )
                })}
                {visibleRows.length === 0 && (
                  <tr>
                    <td colSpan={6} className="px-3 py-3 text-gray-500 font-mono">No open service rows available.</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </CollapsibleModuleCard>
      )
    }

    if (moduleKey === 'tech') {
      const view = moduleView.tech
      const technologies = ((moduleData.technologies as string[]) || []).slice(0, 60)
      const categorized = (moduleData.categorized as Record<string, string[]>) || {}
      const categoryRows = Object.entries(categorized)

      return (
        <CollapsibleModuleCard key={moduleKey} title="Technology Fingerprint" subtitle={`Completed in ${moduleInfo?.duration_ms || 0} ms`} badge={badge}>
          {moduleError && (
            <div className="mt-3 rounded-lg border border-red-500/25 bg-red-500/5 px-3 py-2 text-xs text-red-300 font-mono">
              {moduleError}
            </div>
          )}

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

          <div className="mt-4">
            <div className="text-xs text-gray-500 font-mono mb-2">Detected Technologies</div>
            <TagList items={technologies} emptyText="No technologies detected." />
          </div>

          <div className="mt-4">
            <div className="text-xs text-gray-500 font-mono mb-2">Category Breakdown</div>
            <div className="overflow-x-auto rounded-lg border border-white/10">
              <table className="w-full min-w-[760px] text-sm">
                <thead className="bg-white/5 text-xs text-gray-500 font-mono">
                  <tr>
                    <th className="px-3 py-2 text-left">Category</th>
                    <th className="px-3 py-2 text-left">Technologies</th>
                  </tr>
                </thead>
                <tbody>
                  {categoryRows.map(([category, items]) => (
                    <tr key={category} className="border-t border-white/10 align-top">
                      <td className="px-3 py-2 text-gray-200 font-mono">{category}</td>
                      <td className="px-3 py-2 text-gray-300">{items.join(', ') || '-'}</td>
                    </tr>
                  ))}
                  {categoryRows.length === 0 && (
                    <tr>
                      <td colSpan={2} className="px-3 py-3 text-gray-500 font-mono">No categorized technology rows available.</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </CollapsibleModuleCard>
      )
    }

    if (moduleKey === 'whois') {
      const view = moduleView.whois
      const registrant = (moduleData.registrant as Record<string, unknown>) || {}
      const administrativeContact = (moduleData.administrativeContact as Record<string, unknown>) || {}
      const technicalContact = (moduleData.technicalContact as Record<string, unknown>) || {}
      const nameServers = (moduleData.nameServers as string[]) || []

      return (
        <CollapsibleModuleCard key={moduleKey} title="WHOIS Intelligence" subtitle={`Completed in ${moduleInfo?.duration_ms || 0} ms`} badge={badge}>
          {moduleError && (
            <div className="mt-3 rounded-lg border border-red-500/25 bg-red-500/5 px-3 py-2 text-xs text-red-300 font-mono">
              {moduleError}
            </div>
          )}

          <div className="grid md:grid-cols-2 gap-2 mt-3">
            <KeyValueRow label="Registrar" value={view?.registrar} />
            <KeyValueRow label="Domain Age" value={view?.domain_age_days !== null && view?.domain_age_days !== undefined ? `${view.domain_age_days} days` : 'N/A'} />
            <KeyValueRow label="Expiry Date" value={view?.expiry_date} />
            <KeyValueRow label="Registrant Country" value={view?.registrant_country} />
            <KeyValueRow label="Domain" value={moduleData.domainName as string} />
            <KeyValueRow label="Status" value={moduleData.status as string} />
            <KeyValueRow label="Created" value={moduleData.createdDate as string} />
            <KeyValueRow label="Updated" value={moduleData.updatedDate as string} />
          </div>

          <div className="mt-4 grid lg:grid-cols-3 gap-3">
            <div className="rounded-lg border border-white/10 bg-white/3 p-3">
              <div className="text-xs text-gray-500 font-mono mb-2">Registrant</div>
              <div className="space-y-1 text-xs text-gray-300 font-mono">
                <div>Name: {String(registrant.name || 'N/A')}</div>
                <div>Org: {String(registrant.organization || 'N/A')}</div>
                <div>Email: {String(registrant.email || 'N/A')}</div>
                <div>Country: {String(registrant.country || 'N/A')}</div>
              </div>
            </div>
            <div className="rounded-lg border border-white/10 bg-white/3 p-3">
              <div className="text-xs text-gray-500 font-mono mb-2">Administrative Contact</div>
              <div className="space-y-1 text-xs text-gray-300 font-mono">
                <div>Name: {String(administrativeContact.name || 'N/A')}</div>
                <div>Org: {String(administrativeContact.organization || 'N/A')}</div>
                <div>Email: {String(administrativeContact.email || 'N/A')}</div>
                <div>Country: {String(administrativeContact.country || 'N/A')}</div>
              </div>
            </div>
            <div className="rounded-lg border border-white/10 bg-white/3 p-3">
              <div className="text-xs text-gray-500 font-mono mb-2">Technical Contact</div>
              <div className="space-y-1 text-xs text-gray-300 font-mono">
                <div>Name: {String(technicalContact.name || 'N/A')}</div>
                <div>Org: {String(technicalContact.organization || 'N/A')}</div>
                <div>Email: {String(technicalContact.email || 'N/A')}</div>
                <div>Country: {String(technicalContact.country || 'N/A')}</div>
              </div>
            </div>
          </div>

          <div className="mt-4">
            <div className="text-xs text-gray-500 font-mono mb-2">Name Servers</div>
            <TagList items={nameServers} emptyText="No nameserver records available." />
          </div>
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
          <div className="space-y-4 mb-6">
            <div className="glass-card rounded-2xl">
              <LoadingSpinner label="Running weighted reconnaissance and normalizing intelligence outputs..." />
            </div>

            <div className="glass-card rounded-2xl p-5">
              <div className="flex items-center justify-between gap-3 flex-wrap mb-3">
                <h3 className="text-sm font-semibold text-white">Scan Status Viewer</h3>
                <span className="text-xs font-mono px-2.5 py-1 rounded border border-[#0d6efd]/30 bg-[#0d6efd]/10 text-[#6ea8fe]">
                  {scanProgress.runningLabel ? `Running: ${scanProgress.runningLabel}` : 'Initializing'}
                </span>
              </div>

              <div className="grid grid-cols-3 gap-2 mb-3">
                <div className="rounded-lg border border-white/10 bg-white/3 px-3 py-2">
                  <div className="text-[10px] text-gray-500 font-mono uppercase">Done</div>
                  <div className="text-sm text-green-300 font-mono">{scanProgress.done}</div>
                </div>
                <div className="rounded-lg border border-white/10 bg-white/3 px-3 py-2">
                  <div className="text-[10px] text-gray-500 font-mono uppercase">Running</div>
                  <div className="text-sm text-[#6ea8fe] font-mono">{scanProgress.running}</div>
                </div>
                <div className="rounded-lg border border-white/10 bg-white/3 px-3 py-2">
                  <div className="text-[10px] text-gray-500 font-mono uppercase">Pending</div>
                  <div className="text-sm text-amber-300 font-mono">{scanProgress.pending}</div>
                </div>
              </div>

              <div className="text-[11px] text-gray-500 font-mono mb-3">
                {scanProgress.total > 0
                  ? `${scanProgress.done + scanProgress.running}/${scanProgress.total} modules in progress`
                  : 'Preparing module pipeline...'}
              </div>

              <CompactModuleStatusGrid
                moduleOrder={liveModuleOrder.length > 0 ? liveModuleOrder : moduleOrder}
                moduleLabels={MODULE_LABELS}
                modules={liveModules}
                loading={loading}
                progressStep={0}
              />
            </div>
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
                    {resultModuleOrder.map((moduleKey) => {
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
                moduleOrder={resultModuleOrder}
                moduleLabels={MODULE_LABELS}
                modules={result.modules}
                loading={loading}
                progressStep={0}
              />
            </div>

            <div className="glass-card rounded-2xl p-5">
              <h3 className="text-sm font-semibold text-white mb-3">Detailed Module Breakdown</h3>
              <div className="space-y-3">
                {resultModuleOrder.map((moduleKey) => renderModuleCard(moduleKey))}
              </div>
            </div>
          </div>
        )}
      </div>
    </PageWrapper>
  )
}
