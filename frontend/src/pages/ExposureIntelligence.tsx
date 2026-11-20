import { FormEvent, useEffect, useMemo, useState } from 'react'
import {
  AlertOctagon,
  AlertTriangle,
  ArrowRight,
  BarChart3,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Clock,
  Cpu,
  ExternalLink,
  Filter,
  Flame,
  Globe,
  HelpCircle,
  History,
  Layers,
  Lock,
  Network,
  Radio,
  RefreshCw,
  Search,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Terminal,
  Zap,
} from 'lucide-react'
import PageWrapper from '../components/ui/PageWrapper'
import LoadingSpinner from '../components/ui/LoadingSpinner'
import AttackGraphView from '../components/ui/exposure/AttackGraphView'
import {
  getExposureJobStatus,
  scanExposure,
  startExposureJob,
  getExposureHistory,
  compareExposureScans,
} from '../lib/api'
import type {
  ExposureAssessmentResult,
  ExposureHistoryItem,
  ExposureScanMode,
  NormalizedAsset,
  ExposureFinding,
  VulnerabilityFinding,
  RemediationItem,
} from '../types'

const MODE_OPTIONS: Array<{
  value: ExposureScanMode
  label: string
  helper: string
}> = [
  { value: 'quick', label: 'Quick', helper: 'DNS, web technologies, and top listening ports' },
  { value: 'standard', label: 'Standard', helper: 'Comprehensive reconnaissance, tech fingerprinting, and CVE intelligence' },
  { value: 'deep', label: 'Deep', helper: 'Expanded subdomain enumeration, deep network scan, KEV & EPSS enrichment' },
]

function scoreTone(score: number): string {
  if (score <= 20) return '#22c55e'
  if (score <= 40) return '#84cc16'
  if (score <= 60) return '#f59e0b'
  if (score <= 80) return '#f97316'
  return '#ef4444'
}

function gradeColor(grade: string): string {
  if (grade === 'A+' || grade === 'A') return 'text-green-300 border-green-500/35 bg-green-500/10'
  if (grade === 'B' || grade === 'C') return 'text-amber-300 border-amber-500/35 bg-amber-500/10'
  return 'text-red-300 border-red-500/35 bg-red-500/10'
}

function severityBadge(sev: string): string {
  if (sev === 'CRITICAL') return 'bg-red-500/20 text-red-300 border-red-500/40'
  if (sev === 'HIGH') return 'bg-orange-500/20 text-orange-300 border-orange-500/40'
  if (sev === 'MEDIUM') return 'bg-amber-500/20 text-amber-300 border-amber-500/40'
  return 'bg-blue-500/20 text-blue-300 border-blue-500/40'
}

function statusBadge(status: string): string {
  if (status === 'CONFIRMED') return 'bg-red-950/60 text-red-300 border-red-500/50'
  if (status === 'LIKELY') return 'bg-amber-950/60 text-amber-300 border-amber-500/50'
  if (status === 'POTENTIAL') return 'bg-blue-950/60 text-blue-300 border-blue-500/50'
  return 'bg-gray-800 text-gray-300 border-gray-600'
}

export default function ExposureIntelligence() {
  const [target, setTarget] = useState('')
  const [scanMode, setScanMode] = useState<ExposureScanMode>('standard')
  const [loading, setLoading] = useState(false)
  const [progressMsg, setProgressMsg] = useState('Initializing scan...')
  const [progressPct, setProgressPct] = useState(0)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<ExposureAssessmentResult | null>(null)
  const [activeTab, setActiveTab] = useState<'overview' | 'graph' | 'assets' | 'vulns' | 'config' | 'changes' | 'remediation'>('overview')

  // Search & Filter state for Asset Inventory
  const [assetSearch, setAssetSearch] = useState('')
  const [assetFilter, setAssetFilter] = useState<'ALL' | 'LIVE' | 'CRITICAL' | 'VULNERABLE'>('ALL')
  const [expandedAssetId, setExpandedAssetId] = useState<string | null>(null)
  const [historyList, setHistoryList] = useState<ExposureHistoryItem[]>([])

  const handleScan = async (e: FormEvent) => {
    e.preventDefault()
    const cleanTarget = target.trim()
    if (!cleanTarget) return

    setLoading(true)
    setError(null)
    setProgressMsg('Initiating external exposure assessment...')
    setProgressPct(10)

    try {
      // Start background job for smooth progress updates
      const job = await startExposureJob(cleanTarget, scanMode)
      if (job.error) {
        throw new Error(job.error)
      }

      const jobId = job.job_id
      const pollInterval = setInterval(async () => {
        try {
          const statusRes = await getExposureJobStatus(jobId)
          if (statusRes.status_message) {
            setProgressMsg(statusRes.status_message)
          }
          if (statusRes.progress) {
            setProgressPct(statusRes.progress)
          }

          if (statusRes.status === 'completed' && statusRes.result) {
            clearInterval(pollInterval)
            setResult(statusRes.result)
            setLoading(false)
            fetchHistory(cleanTarget)
          } else if (statusRes.status === 'failed') {
            clearInterval(pollInterval)
            setError(statusRes.error || 'Exposure assessment failed.')
            setLoading(false)
          }
        } catch (err: any) {
          clearInterval(pollInterval)
          // Fallback to direct synchronous scan
          try {
            const direct = await scanExposure(cleanTarget, scanMode)
            setResult(direct)
            setLoading(false)
            fetchHistory(cleanTarget)
          } catch (innerErr: any) {
            setError(innerErr.message || 'Exposure scan failed.')
            setLoading(false)
          }
        }
      }, 1500)
    } catch (err: any) {
      // Fallback direct scan
      try {
        const direct = await scanExposure(cleanTarget, scanMode)
        setResult(direct)
        fetchHistory(cleanTarget)
      } catch (innerErr: any) {
        setError(innerErr.message || 'Exposure assessment could not be completed.')
      } finally {
        setLoading(false)
      }
    }
  }

  const fetchHistory = async (targetDomain: string) => {
    try {
      const res = await getExposureHistory(targetDomain)
      if (res.history) {
        setHistoryList(res.history)
      }
    } catch {
      // Ignore
    }
  }

  // Filtered Assets list
  const filteredAssets = useMemo(() => {
    if (!result?.assets) return []
    return result.assets.filter((a) => {
      // Filter tab
      if (assetFilter === 'LIVE' && !a.is_live) return false
      if (assetFilter === 'CRITICAL' && !['high', 'critical'].includes(a.asset_criticality)) return false
      if (assetFilter === 'VULNERABLE' && a.vulnerabilities.length === 0) return false

      // Search term
      if (assetSearch) {
        const q = assetSearch.toLowerCase()
        const matchesHost = a.hostname.toLowerCase().includes(q)
        const matchesIP = a.ip_addresses.some((ip) => ip.includes(q))
        const matchesTech = a.technologies.some((t) => t.name.toLowerCase().includes(q))
        const matchesCVE = a.vulnerabilities.some((v) => v.cve_id.toLowerCase().includes(q))
        return matchesHost || matchesIP || matchesTech || matchesCVE
      }
      return true
    })
  }, [result?.assets, assetFilter, assetSearch])

  // All vulnerabilities across assets
  const allVulnerabilities = useMemo(() => {
    if (!result?.assets) return []
    const vulns: Array<VulnerabilityFinding & { asset_host: string }> = []
    result.assets.forEach((a) => {
      a.vulnerabilities.forEach((v) => {
        vulns.push({ ...v, asset_host: a.hostname })
      })
    })
    return vulns
  }, [result?.assets])

  return (
    <PageWrapper className="pt-24 pb-16 px-4 sm:px-6">
      <div className="space-y-8 max-w-7xl mx-auto">
        {/* Page Top Title */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-semibold bg-cyan-500/10 text-cyan-300 border border-cyan-500/30">
                EASM Platform v2.0
              </span>
              <span className="text-xs text-gray-500 font-mono">• External Attack Surface Management</span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight mt-2">
              Exposure Intelligence Engine
            </h1>
            <p className="text-sm text-gray-400 mt-1">
              Passive perimeter intelligence, vulnerability correlation, attack surface graph, and explainable exposure scoring.
            </p>
          </div>
        </div>

        {/* Search & Configuration Header Card */}
        <div className="glass-card rounded-2xl border border-white/10 p-6 md:p-8 relative overflow-hidden">
          <div className="absolute -right-20 -top-20 w-80 h-80 rounded-full bg-cyan-500/10 blur-3xl pointer-events-none" />

          <div className="relative z-10 space-y-6">
            <div className="flex flex-wrap items-center justify-between gap-4">
              <div>
                <div className="flex items-center gap-2">
                  <Sparkles size={20} className="text-cyan-400" />
                  <h2 className="text-xl font-bold text-white tracking-wide">
                    External Attack Surface & Exposure Assessment
                  </h2>
                </div>
                <p className="text-sm text-gray-400 mt-1 max-w-3xl">
                  Reuses all passive CyberShield scanners, correlates multi-source signals, enriches with
                  CISA KEV and FIRST EPSS, evaluates asset criticality, and delivers an explainable perimeter exposure score.
                </p>
              </div>

              {/* Security Banner Badge */}
              <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-300 text-xs font-mono">
                <ShieldCheck size={14} />
                <span>100% Passive & Non-Intrusive Analysis</span>
              </div>
            </div>

            <form onSubmit={handleScan} className="space-y-4">
              <div className="flex flex-col md:flex-row gap-3">
                <div className="relative flex-1">
                  <Globe className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-400" size={18} />
                  <input
                    type="text"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    placeholder="Enter target domain or hostname (e.g. example.com, api.domain.org)"
                    className="w-full pl-11 pr-4 py-3.5 rounded-xl bg-black/40 border border-white/15 text-white placeholder-gray-500 focus:outline-none focus:border-cyan-400 font-mono text-sm transition-colors"
                    disabled={loading}
                    required
                  />
                </div>

                <button
                  type="submit"
                  disabled={loading || !target.trim()}
                  className="px-8 py-3.5 rounded-xl font-semibold text-white bg-gradient-to-r from-cyan-600 via-blue-600 to-indigo-600 hover:from-cyan-500 hover:to-indigo-500 transition-all duration-200 shadow-lg shadow-cyan-500/20 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                >
                  {loading ? (
                    <>
                      <div className="h-4 w-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                      <span>Assessing...</span>
                    </>
                  ) : (
                    <>
                      <Zap size={18} />
                      <span>Run Exposure Assessment</span>
                    </>
                  )}
                </button>
              </div>

              {/* Scan Mode Selection Chips */}
              <div className="flex flex-wrap items-center gap-3 pt-1">
                <span className="text-xs text-gray-400 font-mono">Scan Depth Profile:</span>
                {MODE_OPTIONS.map((opt) => (
                  <button
                    key={opt.value}
                    type="button"
                    onClick={() => setScanMode(opt.value)}
                    disabled={loading}
                    className={`px-3 py-1.5 rounded-lg text-xs font-mono transition-all text-left flex items-center gap-2 ${
                      scanMode === opt.value
                        ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/50 shadow-[0_0_12px_rgba(6,182,212,0.25)]'
                        : 'bg-white/5 text-gray-400 hover:text-white border border-white/10'
                    }`}
                  >
                    <span className="font-bold uppercase">{opt.label}</span>
                    <span className="text-[11px] text-gray-500 hidden sm:inline">({opt.helper})</span>
                  </button>
                ))}
              </div>
            </form>

            {/* Active Loading Progress Bar */}
            {loading && (
              <div className="p-4 rounded-xl bg-cyan-950/20 border border-cyan-500/30 space-y-2 animate-pulse">
                <div className="flex justify-between text-xs font-mono">
                  <span className="text-cyan-300 font-medium flex items-center gap-2">
                    <Radio size={14} className="animate-spin text-cyan-400" />
                    {progressMsg}
                  </span>
                  <span className="text-cyan-400 font-bold">{progressPct}%</span>
                </div>
                <div className="h-1.5 w-full bg-white/10 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-gradient-to-r from-cyan-400 to-blue-500 transition-all duration-300"
                    style={{ width: `${progressPct}%` }}
                  />
                </div>
              </div>
            )}

            {error && (
              <div className="p-4 rounded-xl bg-red-950/40 border border-red-500/40 text-red-300 text-sm flex items-center gap-3">
                <AlertTriangle size={18} className="text-red-400 flex-shrink-0" />
                <span>{error}</span>
              </div>
            )}
          </div>
        </div>

        {/* Results Container */}
        {result && (
          <div className="space-y-8">
            {/* Top Score & KPI Dashboard Cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-6 gap-4">
              {/* Card 1: Overall Exposure Score */}
              <div className="lg:col-span-2 glass-card rounded-2xl border border-white/10 p-6 flex flex-col justify-between relative overflow-hidden">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono text-gray-400 uppercase tracking-wider">
                    CyberShield Exposure Score
                  </span>
                  <span className={`px-2.5 py-0.5 rounded text-xs font-bold font-mono border ${gradeColor(result.grade)}`}>
                    Grade {result.grade}
                  </span>
                </div>

                <div className="my-4 flex items-center gap-6">
                  {/* Score circle meter */}
                  <div className="relative h-24 w-24 rounded-full flex items-center justify-center flex-shrink-0">
                    <div
                      className="absolute inset-0 rounded-full"
                      style={{
                        background: `conic-gradient(${scoreTone(result.exposure_score)} ${
                          result.exposure_score * 3.6
                        }deg, rgba(255,255,255,0.08) 0deg)`,
                      }}
                    />
                    <div className="absolute inset-2 rounded-full bg-[#0a0f1d] flex flex-col items-center justify-center">
                      <span className="text-3xl font-extrabold font-mono" style={{ color: scoreTone(result.exposure_score) }}>
                        {result.exposure_score}
                      </span>
                      <span className="text-[9px] text-gray-500 font-mono">/ 100</span>
                    </div>
                  </div>

                  <div className="space-y-1">
                    <div className="text-xs font-mono text-gray-400">STATUS VERDICT</div>
                    <div className="text-lg font-bold text-white tracking-wide">{result.grade_label}</div>
                    <div className="text-xs text-gray-400">Risk Level: <span className="font-semibold text-gray-200">{result.risk_level}</span></div>
                  </div>
                </div>

                <div className="text-[11px] text-gray-500 font-mono">
                  Scan ID: {result.scan_id.slice(0, 8)} • {result.scan_mode.toUpperCase()} MODE ({result.scan_duration_ms}ms)
                </div>
              </div>

              {/* Metric 2: Discovered Assets */}
              <div className="glass-card rounded-2xl border border-white/10 p-5 flex flex-col justify-between">
                <div className="flex items-center justify-between text-gray-400">
                  <span className="text-xs font-mono">ASSETS</span>
                  <Network size={16} className="text-blue-400" />
                </div>
                <div className="my-2">
                  <div className="text-2xl font-bold font-mono text-white">{result.summary.metrics.total_assets}</div>
                  <div className="text-xs text-emerald-400 font-mono mt-0.5">{result.summary.metrics.live_hosts} Live Host(s)</div>
                </div>
                <div className="text-[10px] text-gray-500 font-mono">DNS & Subdomain surface</div>
              </div>

              {/* Metric 3: Open Services */}
              <div className="glass-card rounded-2xl border border-white/10 p-5 flex flex-col justify-between">
                <div className="flex items-center justify-between text-gray-400">
                  <span className="text-xs font-mono">SERVICES</span>
                  <Server size={16} className="text-amber-400" />
                </div>
                <div className="my-2">
                  <div className="text-2xl font-bold font-mono text-white">{result.summary.metrics.open_services}</div>
                  <div className="text-xs text-gray-400 font-mono mt-0.5">Listening Ports</div>
                </div>
                <div className="text-[10px] text-gray-500 font-mono">TCP / UDP exposed</div>
              </div>

              {/* Metric 4: Technologies */}
              <div className="glass-card rounded-2xl border border-white/10 p-5 flex flex-col justify-between">
                <div className="flex items-center justify-between text-gray-400">
                  <span className="text-xs font-mono">TECH STACK</span>
                  <Cpu size={16} className="text-purple-400" />
                </div>
                <div className="my-2">
                  <div className="text-2xl font-bold font-mono text-white">{result.summary.metrics.technologies_count}</div>
                  <div className="text-xs text-gray-400 font-mono mt-0.5">Identified Packages</div>
                </div>
                <div className="text-[10px] text-gray-500 font-mono">Fingerprint Engine</div>
              </div>

              {/* Metric 5: CVEs & CISA KEV */}
              <div className="glass-card rounded-2xl border border-white/10 p-5 flex flex-col justify-between">
                <div className="flex items-center justify-between text-gray-400">
                  <span className="text-xs font-mono">VULNERABILITIES</span>
                  <Flame size={16} className={result.summary.metrics.kev_cves_count > 0 ? 'text-red-400 animate-pulse' : 'text-orange-400'} />
                </div>
                <div className="my-2">
                  <div className="text-2xl font-bold font-mono text-white">{result.summary.metrics.known_cves_count}</div>
                  {result.summary.metrics.kev_cves_count > 0 ? (
                    <div className="text-xs text-red-400 font-mono font-bold mt-0.5 flex items-center gap-1">
                      <Flame size={12} /> {result.summary.metrics.kev_cves_count} In CISA KEV!
                    </div>
                  ) : (
                    <div className="text-xs text-emerald-400 font-mono mt-0.5">0 Active KEV Exploits</div>
                  )}
                </div>
                <div className="text-[10px] text-gray-500 font-mono">NVD & CISA Intelligence</div>
              </div>
            </div>

            {/* Category Exposure Breakdown Bar Meters (Part 12 & 13) */}
            <div className="glass-card rounded-2xl border border-white/10 p-6 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/10 pb-3">
                <div className="flex items-center gap-2">
                  <BarChart3 size={18} className="text-cyan-400" />
                  <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                    Explainable Exposure Contribution Breakdown
                  </h3>
                </div>
                <span className="text-xs text-gray-400 font-mono">5 Category Dimensions (Max 100)</span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4 pt-1">
                {result.score_breakdown && (
                  <>
                    {/* 1. Internet Exposure */}
                    <div className="p-3.5 rounded-xl bg-white/[0.02] border border-white/5 space-y-2">
                      <div className="flex justify-between items-center text-xs font-mono">
                        <span className="text-gray-400">Internet Exposure</span>
                        <span className="text-white font-bold">
                          {result.score_breakdown.internet_exposure.score} / {result.score_breakdown.internet_exposure.max}
                        </span>
                      </div>
                      <div className="h-2 w-full bg-white/10 rounded-full overflow-hidden">
                        <div
                          className="h-full bg-blue-500 rounded-full"
                          style={{
                            width: `${(result.score_breakdown.internet_exposure.score / result.score_breakdown.internet_exposure.max) * 100}%`,
                          }}
                        />
                      </div>
                      <div className="text-[11px] text-gray-400 truncate" title={result.score_breakdown.internet_exposure.evidence.join('; ')}>
                        {result.score_breakdown.internet_exposure.evidence[0] || 'Standard footprint'}
                      </div>
                    </div>

                    {/* 2. Vulnerability */}
                    <div className="p-3.5 rounded-xl bg-white/[0.02] border border-white/5 space-y-2">
                      <div className="flex justify-between items-center text-xs font-mono">
                        <span className="text-gray-400">Vulnerabilities</span>
                        <span className="text-white font-bold">
                          {result.score_breakdown.vulnerability.score} / {result.score_breakdown.vulnerability.max}
                        </span>
                      </div>
                      <div className="h-2 w-full bg-white/10 rounded-full overflow-hidden">
                        <div
                          className="h-full bg-red-500 rounded-full"
                          style={{
                            width: `${(result.score_breakdown.vulnerability.score / result.score_breakdown.vulnerability.max) * 100}%`,
                          }}
                        />
                      </div>
                      <div className="text-[11px] text-gray-400 truncate" title={result.score_breakdown.vulnerability.evidence.join('; ')}>
                        {result.score_breakdown.vulnerability.evidence[0] || 'No known vulnerabilities'}
                      </div>
                    </div>

                    {/* 3. Exploitability */}
                    <div className="p-3.5 rounded-xl bg-white/[0.02] border border-white/5 space-y-2">
                      <div className="flex justify-between items-center text-xs font-mono">
                        <span className="text-gray-400">Exploitability</span>
                        <span className="text-white font-bold">
                          {result.score_breakdown.exploitability.score} / {result.score_breakdown.exploitability.max}
                        </span>
                      </div>
                      <div className="h-2 w-full bg-white/10 rounded-full overflow-hidden">
                        <div
                          className="h-full bg-orange-500 rounded-full"
                          style={{
                            width: `${(result.score_breakdown.exploitability.score / result.score_breakdown.exploitability.max) * 100}%`,
                          }}
                        />
                      </div>
                      <div className="text-[11px] text-gray-400 truncate" title={result.score_breakdown.exploitability.evidence.join('; ')}>
                        {result.score_breakdown.exploitability.evidence[0] || 'Baseline EPSS / no KEV'}
                      </div>
                    </div>

                    {/* 4. Configuration */}
                    <div className="p-3.5 rounded-xl bg-white/[0.02] border border-white/5 space-y-2">
                      <div className="flex justify-between items-center text-xs font-mono">
                        <span className="text-gray-400">Configuration</span>
                        <span className="text-white font-bold">
                          {result.score_breakdown.configuration.score} / {result.score_breakdown.configuration.max}
                        </span>
                      </div>
                      <div className="h-2 w-full bg-white/10 rounded-full overflow-hidden">
                        <div
                          className="h-full bg-amber-500 rounded-full"
                          style={{
                            width: `${(result.score_breakdown.configuration.score / result.score_breakdown.configuration.max) * 100}%`,
                          }}
                        />
                      </div>
                      <div className="text-[11px] text-gray-400 truncate" title={result.score_breakdown.configuration.evidence.join('; ')}>
                        {result.score_breakdown.configuration.evidence[0] || 'Controls configured'}
                      </div>
                    </div>

                    {/* 5. Asset Context */}
                    <div className="p-3.5 rounded-xl bg-white/[0.02] border border-white/5 space-y-2">
                      <div className="flex justify-between items-center text-xs font-mono">
                        <span className="text-gray-400">Asset Context</span>
                        <span className="text-white font-bold">
                          {result.score_breakdown.asset_context.score} / {result.score_breakdown.asset_context.max}
                        </span>
                      </div>
                      <div className="h-2 w-full bg-white/10 rounded-full overflow-hidden">
                        <div
                          className="h-full bg-emerald-500 rounded-full"
                          style={{
                            width: `${(result.score_breakdown.asset_context.score / result.score_breakdown.asset_context.max) * 100}%`,
                          }}
                        />
                      </div>
                      <div className="text-[11px] text-gray-400 truncate" title={result.score_breakdown.asset_context.evidence.join('; ')}>
                        {result.score_breakdown.asset_context.evidence[0] || 'Standard context'}
                      </div>
                    </div>
                  </>
                )}
              </div>
            </div>

            {/* Navigation Tabs Bar */}
            <div className="flex flex-wrap gap-2 border-b border-white/10 pb-3">
              {[
                { id: 'overview', label: 'Priority Exposures', count: result.exposures.length },
                { id: 'graph', label: 'Attack Surface Graph', count: result.graph.nodes.length },
                { id: 'assets', label: 'Asset Inventory', count: result.assets.length },
                { id: 'vulns', label: 'CVE & Vulnerabilities', count: allVulnerabilities.length },
                { id: 'changes', label: 'Change Detection', count: result.change_detection.has_changes ? 1 : 0 },
                { id: 'remediation', label: 'Remediation Roadmap', count: result.remediation_plan.length },
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as any)}
                  className={`px-4 py-2.5 rounded-xl text-xs font-mono font-semibold transition-all flex items-center gap-2 ${
                    activeTab === tab.id
                      ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/50 shadow-[0_0_12px_rgba(6,182,212,0.2)]'
                      : 'bg-white/5 text-gray-400 hover:text-white border border-transparent'
                  }`}
                >
                  <span>{tab.label}</span>
                  <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-black/40 text-gray-300">
                    {tab.count}
                  </span>
                </button>
              ))}
            </div>

            {/* TAB CONTENT 1: OVERVIEW & PRIORITY EXPOSURES */}
            {activeTab === 'overview' && (
              <div className="space-y-6">
                {/* Executive Summary Narrative Card */}
                <div className="glass-card rounded-2xl border border-white/10 p-6 space-y-3">
                  <div className="flex items-center gap-2 text-cyan-400">
                    <Shield size={18} />
                    <h3 className="text-sm font-bold uppercase tracking-wider font-mono">
                      Executive Security Assessment
                    </h3>
                  </div>
                  <p className="text-sm text-gray-300 leading-relaxed">{result.summary.narrative}</p>

                  <div className="flex flex-wrap items-center gap-3 pt-2">
                    <span className="text-xs text-gray-400 font-mono">External Intel Status:</span>
                    {Object.entries(result.source_status).map(([src, stat]) => (
                      <span
                        key={src}
                        className="px-2.5 py-1 rounded-md text-[11px] font-mono bg-white/5 border border-white/10 text-gray-300 flex items-center gap-1.5"
                      >
                        <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
                        {src.replace('_', ' ').toUpperCase()}: {stat}
                      </span>
                    ))}
                  </div>
                </div>

                {/* Priority Correlated Exposures Table (Part 9, 10, 14) */}
                <div className="glass-card rounded-2xl border border-white/10 p-6 space-y-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <AlertOctagon size={18} className="text-red-400" />
                      <h3 className="text-base font-bold text-white">Prioritized External Exposures</h3>
                    </div>
                    <span className="text-xs text-gray-400 font-mono">
                      Correlated multi-source security findings
                    </span>
                  </div>

                  {result.exposures.length === 0 ? (
                    <div className="text-center py-10 text-gray-500 text-sm">
                      <ShieldCheck size={36} className="mx-auto mb-2 text-emerald-400 opacity-60" />
                      No critical exposures or actionable attack vectors detected on this target perimeter.
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {result.exposures.map((exp) => (
                        <div
                          key={exp.finding_id}
                          className="p-4 rounded-xl bg-white/[0.02] border border-white/10 hover:border-white/20 transition-all space-y-3"
                        >
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <div className="flex items-center gap-2.5">
                              <span className={`px-2.5 py-0.5 rounded text-xs font-mono font-bold border ${severityBadge(exp.severity)}`}>
                                {exp.severity}
                              </span>
                              <span className={`px-2 py-0.5 rounded text-[11px] font-mono border ${statusBadge(exp.status)}`}>
                                {exp.status}
                              </span>
                              <h4 className="text-sm font-semibold text-white">{exp.title}</h4>
                            </div>

                            <div className="flex items-center gap-2 text-xs font-mono text-gray-400">
                              <span>Asset: <strong className="text-cyan-300">{exp.asset}</strong></span>
                              <span>•</span>
                              <span>Confidence: <strong>{exp.confidence}%</strong></span>
                            </div>
                          </div>

                          <div className="text-xs text-gray-300 leading-relaxed font-mono bg-black/30 p-2.5 rounded-lg border border-white/5">
                            <span className="text-cyan-400 font-semibold">Correlation Reason: </span>
                            {exp.reason}
                          </div>

                          {/* Evidence Chips */}
                          <div className="space-y-1">
                            <div className="text-[10px] font-mono uppercase text-gray-500">Verified Evidence:</div>
                            <div className="flex flex-wrap gap-1.5">
                              {exp.evidence.map((ev, i) => (
                                <span
                                  key={i}
                                  className="px-2 py-0.5 rounded text-[11px] font-mono bg-white/5 border border-white/5 text-gray-300"
                                >
                                  {ev}
                                </span>
                              ))}
                            </div>
                          </div>

                          {exp.remediation && (
                            <div className="text-xs text-emerald-300/90 pt-1 flex items-start gap-1.5">
                              <CheckCircle2 size={14} className="mt-0.5 text-emerald-400 flex-shrink-0" />
                              <span>{exp.remediation}</span>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* TAB CONTENT 2: ATTACK SURFACE GRAPH */}
            {activeTab === 'graph' && (
              <AttackGraphView
                nodes={result.graph.nodes}
                edges={result.graph.edges}
                paths={result.potential_exposure_paths}
              />
            )}

            {/* TAB CONTENT 3: ASSET INVENTORY */}
            {activeTab === 'assets' && (
              <div className="glass-card rounded-2xl border border-white/10 p-6 space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-4 pb-2 border-b border-white/10">
                  <div>
                    <h3 className="text-base font-bold text-white">Normalized Perimeter Asset Inventory</h3>
                    <p className="text-xs text-gray-400 mt-0.5">
                      Unified record of apex domain, discovered subdomains, IP bindings, open ports, and technologies.
                    </p>
                  </div>

                  {/* Filter & Search Bar */}
                  <div className="flex flex-wrap items-center gap-2">
                    <div className="relative">
                      <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
                      <input
                        type="text"
                        value={assetSearch}
                        onChange={(e) => setAssetSearch(e.target.value)}
                        placeholder="Search hostname, IP, tech..."
                        className="pl-8 pr-3 py-1.5 rounded-lg bg-black/40 border border-white/10 text-xs text-white placeholder-gray-500 focus:outline-none focus:border-cyan-400 font-mono"
                      />
                    </div>

                    <div className="flex gap-1">
                      {(['ALL', 'LIVE', 'CRITICAL', 'VULNERABLE'] as const).map((mode) => (
                        <button
                          key={mode}
                          onClick={() => setAssetFilter(mode)}
                          className={`px-2.5 py-1.5 rounded-lg text-xs font-mono transition-colors ${
                            assetFilter === mode
                              ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                              : 'bg-white/5 text-gray-400 hover:text-white border border-transparent'
                          }`}
                        >
                          {mode}
                        </button>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Assets Table */}
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs font-mono">
                    <thead>
                      <tr className="border-b border-white/10 text-gray-500">
                        <th className="py-3 px-3">HOSTNAME</th>
                        <th className="py-3 px-3">IP ADDRESS(ES)</th>
                        <th className="py-3 px-3">PORTS</th>
                        <th className="py-3 px-3">TECHNOLOGIES</th>
                        <th className="py-3 px-3">CRITICALITY</th>
                        <th className="py-3 px-3">RISK SCORE</th>
                        <th className="py-3 px-3 text-right">DETAILS</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-white/5">
                      {filteredAssets.map((asset) => (
                        <>
                          <tr
                            key={asset.asset_id}
                            className="hover:bg-white/[0.02] transition-colors cursor-pointer"
                            onClick={() =>
                              setExpandedAssetId(expandedAssetId === asset.asset_id ? null : asset.asset_id)
                            }
                          >
                            <td className="py-3 px-3 font-semibold text-white flex items-center gap-2">
                              <span
                                className={`h-2 w-2 rounded-full ${asset.is_live ? 'bg-emerald-400' : 'bg-gray-600'}`}
                                title={asset.is_live ? 'Live Host' : 'Unreachable'}
                              />
                              <span className="hover:text-cyan-300">{asset.hostname}</span>
                            </td>
                            <td className="py-3 px-3 text-gray-300">
                              {asset.ip_addresses.length > 0 ? asset.ip_addresses.join(', ') : '—'}
                            </td>
                            <td className="py-3 px-3 text-amber-300">
                              {asset.ports.length > 0 ? asset.ports.join(', ') : 'None detected'}
                            </td>
                            <td className="py-3 px-3 text-purple-300">
                              {asset.technologies.length > 0
                                ? asset.technologies.map((t) => t.name).slice(0, 3).join(', ') +
                                  (asset.technologies.length > 3 ? '...' : '')
                                : '—'}
                            </td>
                            <td className="py-3 px-3">
                              <span
                                className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold ${
                                  ['high', 'critical'].includes(asset.asset_criticality)
                                    ? 'bg-red-500/20 text-red-300 border border-red-500/30'
                                    : 'bg-white/5 text-gray-400'
                                }`}
                                title={asset.criticality_reason}
                              >
                                {asset.asset_criticality}
                              </span>
                            </td>
                            <td className="py-3 px-3 font-bold" style={{ color: scoreTone(asset.risk_score) }}>
                              {asset.risk_score} / 100
                            </td>
                            <td className="py-3 px-3 text-right text-gray-400">
                              <ChevronDown
                                size={14}
                                className={`inline-block transition-transform ${
                                  expandedAssetId === asset.asset_id ? 'rotate-180' : ''
                                }`}
                              />
                            </td>
                          </tr>

                          {/* Expanded Details Row */}
                          {expandedAssetId === asset.asset_id && (
                            <tr key={`${asset.asset_id}-details`} className="bg-black/40">
                              <td colSpan={7} className="p-4 space-y-3 border-b border-white/10">
                                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono">
                                  <div className="space-y-1">
                                    <div className="text-gray-500 uppercase">Criticality Rationale</div>
                                    <div className="text-gray-300">{asset.criticality_reason}</div>
                                  </div>
                                  <div className="space-y-1">
                                    <div className="text-gray-500 uppercase">Listening Services</div>
                                    <div className="text-gray-300">
                                      {asset.services.length > 0 ? (
                                        asset.services.map((s, idx) => (
                                          <div key={idx}>
                                            Port {s.port}/{s.protocol}: {s.service} {s.banner ? `(${s.banner})` : ''}
                                          </div>
                                        ))
                                      ) : (
                                        <span>No detailed banner grabs available</span>
                                      )}
                                    </div>
                                  </div>
                                  <div className="space-y-1">
                                    <div className="text-gray-500 uppercase">Discovered Technologies</div>
                                    <div className="text-gray-300 flex flex-wrap gap-1">
                                      {asset.technologies.map((t, idx) => (
                                        <span key={idx} className="px-2 py-0.5 rounded bg-white/5 text-[11px]">
                                          {t.name} {t.version || ''}
                                        </span>
                                      ))}
                                    </div>
                                  </div>
                                </div>
                              </td>
                            </tr>
                          )}
                        </>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* TAB CONTENT 4: VULNERABILITIES & CVE INTEL */}
            {activeTab === 'vulns' && (
              <div className="glass-card rounded-2xl border border-white/10 p-6 space-y-4">
                <div className="flex items-center justify-between border-b border-white/10 pb-3">
                  <div>
                    <h3 className="text-base font-bold text-white flex items-center gap-2">
                      <Flame size={18} className="text-red-400" />
                      CVE & Threat Intelligence Registry
                    </h3>
                    <p className="text-xs text-gray-400 mt-0.5">
                      Enriched with CISA Known Exploited Vulnerabilities (KEV) and FIRST Exploit Prediction Scoring System (EPSS).
                    </p>
                  </div>
                  <span className="text-xs font-mono text-gray-400">{allVulnerabilities.length} Matching CVEs</span>
                </div>

                {allVulnerabilities.length === 0 ? (
                  <div className="text-center py-12 text-gray-500 text-sm">
                    <ShieldCheck size={36} className="mx-auto mb-2 text-emerald-400 opacity-60" />
                    No known CVE vulnerabilities identified in verified software versions.
                  </div>
                ) : (
                  <div className="space-y-3">
                    {allVulnerabilities.map((vuln, idx) => (
                      <div
                        key={`${vuln.cve_id}-${idx}`}
                        className="p-4 rounded-xl bg-white/[0.02] border border-white/10 hover:border-white/20 transition-all space-y-3"
                      >
                        <div className="flex flex-wrap items-center justify-between gap-3">
                          <div className="flex items-center gap-3">
                            <span className="text-base font-bold font-mono text-white tracking-wide">
                              {vuln.cve_id}
                            </span>
                            <span className={`px-2 py-0.5 rounded text-[10px] font-mono border ${statusBadge(vuln.status)}`}>
                              {vuln.status}
                            </span>
                            {vuln.kev && (
                              <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-red-500/20 text-red-300 border border-red-500/40 flex items-center gap-1 shadow-[0_0_10px_rgba(239,68,68,0.25)]">
                                <Flame size={12} /> CISA KEV (Actively Exploited)
                              </span>
                            )}
                          </div>

                          <div className="flex items-center gap-3 text-xs font-mono">
                            <span className="text-gray-400">CVSS: <strong className="text-red-400">{vuln.cvss}</strong></span>
                            <span className="text-gray-400">EPSS: <strong className="text-cyan-300">{(vuln.epss * 100).toFixed(1)}%</strong></span>
                            <span className="text-gray-400">Host: <strong className="text-gray-200">{vuln.asset_host}</strong></span>
                          </div>
                        </div>

                        <p className="text-xs text-gray-300 leading-relaxed">{vuln.summary}</p>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono bg-black/30 p-2.5 rounded-lg border border-white/5">
                          <div>
                            <span className="text-gray-500">Component / Detected Version: </span>
                            <span className="text-white font-semibold">
                              {vuln.technology} ({vuln.detected_version || 'Unconfirmed'})
                            </span>
                          </div>
                          <div>
                            <span className="text-gray-500">Affected Version Range: </span>
                            <span className="text-amber-300">{vuln.affected_version_range}</span>
                          </div>
                        </div>

                        {vuln.remediation && (
                          <div className="text-xs text-emerald-300 pt-1 flex items-start gap-1.5">
                            <CheckCircle2 size={14} className="mt-0.5 text-emerald-400 flex-shrink-0" />
                            <span><strong>Remediation:</strong> {vuln.remediation}</span>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* TAB CONTENT 5: CHANGE DETECTION & DRIFT */}
            {activeTab === 'changes' && (
              <div className="glass-card rounded-2xl border border-white/10 p-6 space-y-4">
                <div className="flex items-center justify-between border-b border-white/10 pb-3">
                  <div>
                    <h3 className="text-base font-bold text-white flex items-center gap-2">
                      <History size={18} className="text-cyan-400" />
                      Perimeter Drift & Change Detection
                    </h3>
                    <p className="text-xs text-gray-400 mt-0.5">
                      Tracks asset additions, decommissioned services, port changes, and resolved vulnerabilities.
                    </p>
                  </div>

                  <span className="text-xs font-mono text-gray-400">
                    Delta: <strong className={result.change_detection.score_delta > 0 ? 'text-red-400' : 'text-emerald-400'}>
                      {result.change_detection.score_delta > 0 ? `+${result.change_detection.score_delta}` : result.change_detection.score_delta} pts
                    </strong>
                  </span>
                </div>

                <div className="p-4 rounded-xl bg-white/[0.02] border border-white/10 space-y-3">
                  <div className="text-sm font-semibold text-white flex items-center gap-2">
                    <Sparkles size={16} className="text-cyan-400" />
                    <span>Summary of Changes</span>
                  </div>
                  <p className="text-xs font-mono text-gray-300">{result.change_detection.summary}</p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* New additions */}
                  <div className="p-4 rounded-xl bg-emerald-950/20 border border-emerald-500/20 space-y-2">
                    <div className="text-xs font-mono font-bold text-emerald-400 uppercase">
                      + Added / Newly Discovered Perimeter Elements
                    </div>
                    {result.change_detection.new_subdomains.length === 0 &&
                    result.change_detection.new_ports.length === 0 &&
                    result.change_detection.new_vulnerabilities.length === 0 ? (
                      <div className="text-xs text-gray-500 font-mono">No new assets or open ports discovered</div>
                    ) : (
                      <ul className="text-xs font-mono text-gray-300 space-y-1">
                        {result.change_detection.new_subdomains.map((sub, i) => (
                          <li key={i} className="text-emerald-300">+ New subdomain: {sub}</li>
                        ))}
                        {result.change_detection.new_ports.map((p, i) => (
                          <li key={i} className="text-emerald-300">+ New listening port: {p.host}:{p.port}</li>
                        ))}
                        {result.change_detection.new_vulnerabilities.map((v, i) => (
                          <li key={i} className="text-red-300">+ New vulnerability: {v.cve_id} on {v.host}</li>
                        ))}
                      </ul>
                    )}
                  </div>

                  {/* Decommissioned / Removed */}
                  <div className="p-4 rounded-xl bg-blue-950/20 border border-blue-500/20 space-y-2">
                    <div className="text-xs font-mono font-bold text-blue-400 uppercase">
                      - Closed Ports / Resolved Vulnerabilities
                    </div>
                    {result.change_detection.closed_ports.length === 0 &&
                    result.change_detection.resolved_vulnerabilities.length === 0 &&
                    result.change_detection.removed_subdomains.length === 0 ? (
                      <div className="text-xs text-gray-500 font-mono">No closed ports or resolved items detected</div>
                    ) : (
                      <ul className="text-xs font-mono text-gray-300 space-y-1">
                        {result.change_detection.removed_subdomains.map((sub, i) => (
                          <li key={i} className="text-gray-400">- Removed subdomain: {sub}</li>
                        ))}
                        {result.change_detection.closed_ports.map((p, i) => (
                          <li key={i} className="text-emerald-400">- Port closed: {p.host}:{p.port}</li>
                        ))}
                        {result.change_detection.resolved_vulnerabilities.map((v, i) => (
                          <li key={i} className="text-emerald-400">- Vulnerability resolved: {v.cve_id}</li>
                        ))}
                      </ul>
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* TAB CONTENT 6: REMEDIATION ROADMAP */}
            {activeTab === 'remediation' && (
              <div className="glass-card rounded-2xl border border-white/10 p-6 space-y-4">
                <div className="flex items-center justify-between border-b border-white/10 pb-3">
                  <div>
                    <h3 className="text-base font-bold text-white flex items-center gap-2">
                      <CheckCircle2 size={18} className="text-emerald-400" />
                      Prioritized Defensive Remediation Roadmap
                    </h3>
                    <p className="text-xs text-gray-400 mt-0.5">
                      Actionable, defensive steps to harden external assets and reduce perimeter exposure score.
                    </p>
                  </div>
                  <span className="text-xs font-mono text-gray-400">
                    {result.remediation_plan.length} Action Items
                  </span>
                </div>

                <div className="space-y-4">
                  {result.remediation_plan.map((item) => (
                    <div
                      key={item.step_number}
                      className="p-5 rounded-xl bg-white/[0.02] border border-white/10 space-y-3"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex items-center gap-3">
                          <span className="h-6 w-6 rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 flex items-center justify-center font-mono text-xs font-bold">
                            {item.step_number}
                          </span>
                          <span className={`px-2.5 py-0.5 rounded text-xs font-mono font-bold border ${severityBadge(item.severity)}`}>
                            {item.priority_label}
                          </span>
                          <h4 className="text-sm font-semibold text-white">{item.title}</h4>
                        </div>

                        <span className="text-xs font-mono text-gray-400">
                          Effort: <strong className="text-gray-200">{item.effort}</strong>
                        </span>
                      </div>

                      <div className="text-xs text-gray-400 font-mono">
                        Target Asset(s): <strong className="text-cyan-300">{item.affected_assets.join(', ')}</strong>
                      </div>

                      {/* Checklist steps */}
                      <div className="space-y-1.5 pt-2 border-t border-white/5">
                        <div className="text-xs text-gray-400 font-mono font-semibold">Recommended Steps:</div>
                        <ol className="list-decimal list-inside text-xs text-gray-300 space-y-1 font-mono pl-1">
                          {item.steps.map((step, sIdx) => (
                            <li key={sIdx}>{step}</li>
                          ))}
                        </ol>
                      </div>

                      <div className="text-[11px] text-gray-500 font-mono pt-1">
                        <strong>Verification:</strong> {item.verification}
                      </div>
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
