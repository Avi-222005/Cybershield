import { useState, FormEvent } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Globe, Search, Info, ChevronDown, ChevronUp, ExternalLink, Ruler, Network, GitBranch, Code, KeyRound, ShieldCheck, Link2, Globe2, Circle, AlertTriangle, Languages, FolderTree, CheckCircle2, XCircle } from 'lucide-react'
import PageWrapper from '../components/ui/PageWrapper'
import ResultBadge from '../components/ui/ResultBadge'
import ScoreGauge from '../components/ui/ScoreGauge'
import VendorTable from '../components/ui/VendorTable'
import LoadingSpinner from '../components/ui/LoadingSpinner'
import { checkUrl } from '../lib/api'
import { getSeverityColor } from '../lib/utils'
import type { PhishingResult } from '../types'

// Define the 12 custom indicators with their weights
const INDICATOR_CONFIG = [
  { id: 1, key: 'url_length', name: 'URL Length', icon: Ruler, weight: 8, threshold: '> 75 chars' },
  { id: 2, key: 'uses_ip', name: 'IP Address', icon: Network, weight: 20, threshold: 'IP in URL' },
  { id: 3, key: 'subdomain_count', name: 'Subdomain Count', icon: GitBranch, weight: 12, threshold: '> 3 subdomains' },
  { id: 4, key: 'special_chars', name: 'Special Characters', icon: Code, weight: 10, threshold: '@ or excessive -/_' },
  { id: 5, key: 'suspicious_keywords', name: 'Suspicious Keywords', icon: KeyRound, weight: 15, threshold: 'login, verify, etc.' },
  { id: 6, key: 'https_misuse', name: 'HTTPS Security', icon: ShieldCheck, weight: 12, threshold: 'https in domain' },
  { id: 7, key: 'url_shortener', name: 'URL Shortener', icon: Link2, weight: 5, threshold: 'bit.ly, tinyurl' },
  { id: 8, key: 'high_risk_tld', name: 'High-Risk TLD', icon: Globe2, weight: 10, threshold: '.tk, .xyz, .top' },
  { id: 9, key: 'excessive_dots', name: 'Excessive Dots', icon: Circle, weight: 3, threshold: '> 4 dots' },
  { id: 10, key: 'brand_spoofing', name: 'Brand Spoofing', icon: AlertTriangle, weight: 15, threshold: 'paypal, amazon' },
  { id: 11, key: 'punycode', name: 'Punycode (IDN)', icon: Languages, weight: 5, threshold: 'xn-- prefix' },
  { id: 12, key: 'path_depth', name: 'Path Depth', icon: FolderTree, weight: 5, threshold: '> 5 levels' },
]

export default function PhishingChecker() {
  const [url, setUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<PhishingResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [showReasons, setShowReasons] = useState(true)
  const [showIndicators, setShowIndicators] = useState(true)

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    const trimmed = url.trim()
    if (!trimmed) return

    setLoading(true)
    setResult(null)
    setError(null)

    try {
      const data = await checkUrl(trimmed)
      setResult(data)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Analysis failed. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  // Process analysis features into indicator data
  function getIndicators() {
    if (!result?.analysis_features) return []
    const f = result.analysis_features
    
    return [
      {
        ...INDICATOR_CONFIG[0],
        value: `${f.url_length || 0} chars`,
        triggered: (f.url_length || 0) >= 75,
        status: (f.url_length || 0) < 54 ? 'success' : (f.url_length || 0) < 75 ? 'warning' : 'danger',
        description: (f.url_length || 0) >= 75 ? 'Unusually long URL detected' : 'URL length is normal',
      },
      {
        ...INDICATOR_CONFIG[1],
        value: f.uses_ip ? 'Detected' : 'Not used',
        triggered: f.uses_ip || false,
        status: f.uses_ip ? 'danger' : 'success',
        description: f.uses_ip ? 'URL uses IP instead of domain' : 'Uses proper domain name',
      },
      {
        ...INDICATOR_CONFIG[2],
        value: `${f.subdomain_count || 0} found`,
        triggered: (f.subdomain_count || 0) > 3,
        status: (f.subdomain_count || 0) <= 2 ? 'success' : (f.subdomain_count || 0) <= 3 ? 'warning' : 'danger',
        description: (f.subdomain_count || 0) > 3 ? 'Excessive subdomains detected' : 'Normal subdomain structure',
      },
      {
        ...INDICATOR_CONFIG[3],
        value: f.special_chars?.is_suspicious ? 'Suspicious' : 'Normal',
        triggered: f.special_chars?.is_suspicious || false,
        status: f.special_chars?.is_suspicious ? 'danger' : 'success',
        description: f.special_chars?.is_suspicious ? 'Unusual special characters found' : 'No suspicious characters',
      },
      {
        ...INDICATOR_CONFIG[4],
        value: (f.suspicious_keywords_found || 0) === 0 ? 'None' : `${f.suspicious_keywords_found} found`,
        triggered: (f.suspicious_keywords_found || 0) > 0,
        status: (f.suspicious_keywords_found || 0) === 0 ? 'success' : (f.suspicious_keywords_found || 0) <= 2 ? 'warning' : 'danger',
        description: (f.suspicious_keywords_found || 0) > 0 ? `Found: ${(f.suspicious_keywords_list || []).slice(0, 3).join(', ')}` : 'No phishing keywords detected',
      },
      {
        ...INDICATOR_CONFIG[5],
        value: f.https_in_domain ? 'Deceptive' : f.uses_https ? 'Secure' : 'Not secure',
        triggered: f.https_in_domain || f.is_http_only || false,
        status: f.https_in_domain ? 'danger' : f.uses_https ? 'success' : 'warning',
        description: f.https_in_domain ? 'HTTPS misuse detected' : f.uses_https ? 'Proper HTTPS' : 'No HTTPS',
      },
      {
        ...INDICATOR_CONFIG[6],
        value: f.is_url_shortener ? 'Detected' : 'Not used',
        triggered: f.is_url_shortener || false,
        status: f.is_url_shortener ? 'warning' : 'success',
        description: f.is_url_shortener ? 'URL shortening service detected' : 'Direct URL link',
      },
      {
        ...INDICATOR_CONFIG[7],
        value: f.high_risk_tld ? (f.tld_name || 'Risky') : 'Standard',
        triggered: f.high_risk_tld || false,
        status: f.high_risk_tld ? 'danger' : 'success',
        description: f.high_risk_tld ? 'Known risky top-level domain' : 'Standard TLD',
      },
      {
        ...INDICATOR_CONFIG[8],
        value: `${f.dot_count || 0} dots`,
        triggered: f.excessive_dots || false,
        status: f.excessive_dots ? 'warning' : 'success',
        description: f.excessive_dots ? 'Too many dots in domain' : 'Normal dot count',
      },
      {
        ...INDICATOR_CONFIG[9],
        value: f.brand_spoofing ? 'Detected' : 'None',
        triggered: f.brand_spoofing || false,
        status: f.brand_spoofing ? 'danger' : 'success',
        description: f.brand_spoofing ? `Mimics: ${(f.brands_found || []).join(', ')}` : 'No brand impersonation',
      },
      {
        ...INDICATOR_CONFIG[10],
        value: f.has_punycode ? 'Detected' : 'Not used',
        triggered: f.has_punycode || false,
        status: f.has_punycode ? 'warning' : 'success',
        description: f.has_punycode ? 'Internationalized domain detected' : 'Standard ASCII domain',
      },
      {
        ...INDICATOR_CONFIG[11],
        value: `${f.path_depth || 0} levels`,
        triggered: f.path_depth_suspicious || false,
        status: f.path_depth_suspicious ? 'warning' : 'success',
        description: f.path_depth_suspicious ? 'Unusually deep URL path' : 'Normal path structure',
      },
    ]
  }

  const indicators = getIndicators()
  const passedCount = indicators.filter(i => !i.triggered).length
  const failedCount = indicators.filter(i => i.triggered).length

  return (
    <PageWrapper>
      <div className="max-w-4xl mx-auto px-4 sm:px-6 pt-28 pb-20">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-2.5 mb-2">
            <div className="p-2 rounded-lg bg-[#0d6efd]/10 border border-[#0d6efd]/20">
              <Globe size={18} className="text-[#0d6efd]" />
            </div>
            <h1 className="text-2xl font-bold text-white">URL Phishing Checker</h1>
          </div>
          <p className="text-gray-500 text-sm ml-10">
            Hybrid AI analysis — 12 custom indicators + 70+ VirusTotal security engines
          </p>
        </div>

        {/* Input form */}
        <form onSubmit={handleSubmit} className="glass-card rounded-2xl p-5 mb-6">
          <label className="block text-xs font-mono text-gray-400 mb-2 uppercase tracking-wider">
            URL to Analyze
          </label>
          <div className="flex gap-3">
            <input
              type="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example.com/suspicious-page"
              className="cyber-input flex-1 px-4 py-3 rounded-xl text-sm font-mono"
              required
              disabled={loading}
            />
            <button
              type="submit"
              disabled={loading || !url.trim()}
              className="flex items-center gap-2 px-6 py-3 bg-[#0d6efd] hover:bg-[#0b5ed7] disabled:opacity-50 disabled:cursor-not-allowed !text-white font-semibold rounded-xl transition-colors text-sm shrink-0"
            >
              <Search size={16} />
              Analyze
            </button>
          </div>
          <p className="text-xs text-gray-600 mt-2.5">
            <Info size={11} className="inline mr-1" />
            Analysis uses VirusTotal API — first scan may take 10–30 seconds.
          </p>
        </form>

        {/* Loading */}
        <AnimatePresence>
          {loading && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="glass-card rounded-2xl"
            >
              <LoadingSpinner label="Scanning with 70+ security engines…" />
            </motion.div>
          )}
        </AnimatePresence>

        {/* Error */}
        {error && !loading && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className="glass-card rounded-2xl p-5 border border-red-500/25 bg-red-500/5"
          >
            <p className="text-red-400 text-sm font-mono">{error}</p>
          </motion.div>
        )}

        {/* Results */}
        <AnimatePresence>
          {result && !loading && (
            <motion.div
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.35 }}
              className="space-y-5"
            >
              {/* ── Top card: verdict + score ── */}
              <div className="glass-card rounded-2xl p-6">
                <div className="flex flex-col sm:flex-row items-start sm:items-center gap-6">
                  {/* Score gauge */}
                  <div className="shrink-0">
                    <ScoreGauge score={result.final_score} />
                  </div>

                  {/* Verdict details */}
                  <div className="flex-1 min-w-0">
                    <div className="flex flex-wrap items-center gap-3 mb-3">
                      <ResultBadge verdict={result.verdict} size="lg" />
                      <span
                        className="text-xs px-2.5 py-1 rounded-full border font-mono"
                        style={{
                          color: getSeverityColor(result.severity),
                          borderColor: `${getSeverityColor(result.severity)}40`,
                          background: `${getSeverityColor(result.severity)}10`,
                        }}
                      >
                        {result.severity} severity
                      </span>
                    </div>

                    <p className="text-sm text-gray-300 leading-relaxed mb-4">
                      {result.security_recommendation}
                    </p>

                    {/* Score breakdown */}
                    <div className="grid grid-cols-2 gap-3">
                      <div className="bg-white/3 rounded-lg px-3 py-2.5">
                        <div className="text-xs text-gray-500 font-mono mb-0.5">Custom Analysis</div>
                        <div className="text-lg font-bold font-mono text-[#0d6efd]">
                          {result.custom_score}<span className="text-xs text-gray-500">/100</span>
                        </div>
                        <div className="text-xs text-gray-600">65% weight</div>
                      </div>
                      <div className="bg-white/3 rounded-lg px-3 py-2.5">
                        <div className="text-xs text-gray-500 font-mono mb-0.5">API Intelligence</div>
                        <div className="text-lg font-bold font-mono text-blue-400">
                          {result.api_score}<span className="text-xs text-gray-500">/70</span>
                        </div>
                        <div className="text-xs text-gray-600">35% weight</div>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Analyzed URL */}
                <div className="mt-4 pt-4 border-t border-cyber-border flex items-center gap-2">
                  <span className="text-xs text-gray-500 font-mono shrink-0">URL:</span>
                  <span className="text-xs text-[#0d6efd] font-mono truncate">{result.analyzed_url}</span>
                  <a
                    href={result.analyzed_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="shrink-0 text-gray-600 hover:text-[#0d6efd] transition-colors"
                  >
                    <ExternalLink size={12} />
                  </a>
                </div>
              </div>

              {/* ── Custom Analysis Indicators (12 indicators) ── */}
              {result.analysis_features && (
                <div className="glass-card rounded-2xl overflow-hidden">
                  <button
                    onClick={() => setShowIndicators((v) => !v)}
                    className="w-full flex items-center justify-between px-5 py-4 hover:bg-white/3 transition-colors"
                  >
                    <div className="flex items-center gap-3">
                      <h3 className="text-sm font-semibold text-white">
                        Custom Analysis Indicators
                        <span className="ml-2 text-xs text-gray-500 font-mono font-normal">
                          (12 security parameters)
                        </span>
                      </h3>
                    </div>
                    <div className="flex items-center gap-3">
                      <span className="flex items-center gap-1 text-xs font-mono text-green-400">
                        <CheckCircle2 size={12} /> {passedCount}
                      </span>
                      <span className="flex items-center gap-1 text-xs font-mono text-red-400">
                        <XCircle size={12} /> {failedCount}
                      </span>
                      {showIndicators ? <ChevronUp size={16} className="text-gray-500" /> : <ChevronDown size={16} className="text-gray-500" />}
                    </div>
                  </button>
                  {showIndicators && (
                    <div className="px-5 pb-5">
                      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3">
                        {indicators.map((ind) => {
                          const Icon = ind.icon
                          const statusColors = {
                            success: { bg: 'bg-green-500/10', border: 'border-green-500/30', text: 'text-green-400', iconBg: 'bg-green-500/20' },
                            warning: { bg: 'bg-yellow-500/10', border: 'border-yellow-500/30', text: 'text-yellow-400', iconBg: 'bg-yellow-500/20' },
                            danger: { bg: 'bg-red-500/10', border: 'border-red-500/30', text: 'text-red-400', iconBg: 'bg-red-500/20' },
                          }
                          const colors = statusColors[ind.status as keyof typeof statusColors] || statusColors.success
                          
                          return (
                            <motion.div
                              key={ind.id}
                              initial={{ opacity: 0, y: 10 }}
                              animate={{ opacity: 1, y: 0 }}
                              transition={{ delay: ind.id * 0.03 }}
                              className={`relative ${colors.bg} ${colors.border} border rounded-xl p-3 hover:scale-[1.02] transition-transform cursor-default`}
                            >
                              {/* Indicator number */}
                              <span className="absolute top-2 right-2 text-[10px] text-gray-600 font-mono">#{ind.id}</span>
                              
                              {/* Header */}
                              <div className="flex items-center gap-2 mb-2">
                                <div className={`p-1.5 rounded-lg ${colors.iconBg}`}>
                                  <Icon size={14} className={colors.text} />
                                </div>
                                <div className="flex-1 min-w-0">
                                  <h4 className="text-xs font-semibold text-white truncate">{ind.name}</h4>
                                  <span className={`text-[10px] font-mono ${colors.text}`}>Weight: {ind.weight}%</span>
                                </div>
                                {ind.triggered ? (
                                  <XCircle size={16} className="text-red-400 shrink-0" />
                                ) : (
                                  <CheckCircle2 size={16} className="text-green-400 shrink-0" />
                                )}
                              </div>
                              
                              {/* Value badge */}
                              <div className={`inline-block text-[11px] font-mono px-2 py-0.5 rounded-md ${colors.bg} ${colors.text} border ${colors.border} mb-1.5`}>
                                {ind.value}
                              </div>
                              
                              {/* Description */}
                              <p className="text-[10px] text-gray-500 leading-tight mb-1">{ind.description}</p>
                              
                              {/* Threshold */}
                              <div className="text-[9px] text-gray-600 font-mono">
                                Threshold: {ind.threshold}
                              </div>
                            </motion.div>
                          )
                        })}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* ── Detection reasons ── */}
              {result.detection_reasons?.length > 0 && (
                <div className="glass-card rounded-2xl overflow-hidden">
                  <button
                    onClick={() => setShowReasons((v) => !v)}
                    className="w-full flex items-center justify-between px-5 py-4 hover:bg-white/3 transition-colors"
                  >
                    <h3 className="text-sm font-semibold text-white">
                      Detection Reasons
                      <span className="ml-2 text-xs text-gray-500 font-mono font-normal">
                        ({result.detection_reasons.length} indicators)
                      </span>
                    </h3>
                    {showReasons ? <ChevronUp size={16} className="text-gray-500" /> : <ChevronDown size={16} className="text-gray-500" />}
                  </button>
                  {showReasons && (
                    <div className="px-5 pb-4 space-y-1.5">
                      {result.detection_reasons.map((reason, i) => (
                        <div key={i} className="text-sm text-gray-400 font-mono bg-white/3 rounded-lg px-3 py-2">
                          {reason}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* ── Domain info ── */}
              {result.domain_info && (
                <div className="glass-card rounded-2xl p-5">
                  <h3 className="text-sm font-semibold text-white mb-4">Domain Information</h3>
                  <div className="grid sm:grid-cols-2 gap-3">
                    {[
                      { label: 'Registrar', value: result.domain_info.registrar },
                      { label: 'Status', value: result.domain_info.domain_status },
                      { label: 'Created', value: result.domain_info.creation_date },
                      { label: 'Expires', value: result.domain_info.expiration_date },
                      { label: 'Last Updated', value: result.domain_info.last_updated },
                      { label: 'Country', value: result.domain_info.registrant_country },
                    ].map(({ label, value }) =>
                      value && value !== 'N/A' && value !== 'Error' ? (
                        <div key={label} className="bg-white/3 rounded-lg px-3 py-2.5">
                          <div className="text-xs text-gray-500 font-mono mb-0.5">{label}</div>
                          <div className="text-sm text-gray-200 truncate">{value}</div>
                        </div>
                      ) : null,
                    )}
                  </div>
                  {result.domain_info.name_servers?.length > 0 && (
                    <div className="mt-3">
                      <div className="text-xs text-gray-500 font-mono mb-1.5">Name Servers</div>
                      <div className="flex flex-wrap gap-1.5">
                        {result.domain_info.name_servers.map((ns) => (
                          <span key={ns} className="text-xs font-mono text-[#0d6efd]/80 bg-[#0d6efd]/5 border border-[#0d6efd]/15 px-2 py-0.5 rounded">
                            {ns}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* ── URLhaus threat intelligence ── */}
              {result.urlhaus?.enabled && (
                <div className="glass-card rounded-2xl p-5">
                  <h3 className="text-sm font-semibold text-white mb-4">URLhaus Intelligence</h3>
                  {result.urlhaus.matched ? (
                    <div className="space-y-3">
                      <div className="flex flex-wrap gap-2">
                        <span className="text-xs px-2.5 py-1 rounded-full border border-red-500/30 bg-red-500/10 text-red-400 font-mono">
                          Matched in URLhaus
                        </span>
                        {result.urlhaus.url_status && (
                          <span className="text-xs px-2.5 py-1 rounded-full border border-yellow-500/30 bg-yellow-500/10 text-yellow-400 font-mono">
                            Status: {result.urlhaus.url_status}
                          </span>
                        )}
                        {result.urlhaus.threat && (
                          <span className="text-xs px-2.5 py-1 rounded-full border border-orange-500/30 bg-orange-500/10 text-orange-400 font-mono">
                            Threat: {result.urlhaus.threat}
                          </span>
                        )}
                      </div>

                      <div className="grid sm:grid-cols-2 gap-3">
                        {[
                          { label: 'URLhaus ID', value: result.urlhaus.id },
                          { label: 'Host', value: result.urlhaus.host },
                          { label: 'Date Added', value: result.urlhaus.date_added },
                          { label: 'Last Online', value: result.urlhaus.last_online || 'N/A' },
                          { label: 'Reporter', value: result.urlhaus.reporter },
                          { label: 'Payload Count', value: String(result.urlhaus.payload_count ?? 0) },
                          { label: 'SURBL', value: result.urlhaus.blacklists?.surbl },
                          { label: 'Spamhaus DBL', value: result.urlhaus.blacklists?.spamhaus_dbl },
                        ].map(({ label, value }) =>
                          value && value !== 'N/A' ? (
                            <div key={label} className="bg-white/3 rounded-lg px-3 py-2.5">
                              <div className="text-xs text-gray-500 font-mono mb-0.5">{label}</div>
                              <div className="text-sm text-gray-200 break-all">{value}</div>
                            </div>
                          ) : null,
                        )}
                      </div>

                      {result.urlhaus.tags && result.urlhaus.tags.length > 0 && (
                        <div>
                          <div className="text-xs text-gray-500 font-mono mb-1.5">Tags</div>
                          <div className="flex flex-wrap gap-1.5">
                            {result.urlhaus.tags.map((tag) => (
                              <span key={tag} className="text-xs font-mono text-red-300 bg-red-500/10 border border-red-500/20 px-2 py-0.5 rounded">
                                {tag}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}

                      {result.urlhaus.urlhaus_reference && (
                        <a
                          href={result.urlhaus.urlhaus_reference}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1 text-xs font-mono text-[#0d6efd] hover:text-blue-300"
                        >
                          View URLhaus Entry <ExternalLink size={12} />
                        </a>
                      )}
                    </div>
                  ) : (
                    <div className="text-sm text-gray-400 font-mono">
                      {result.urlhaus.query_status === 'no_results'
                        ? 'No URLhaus match found for this URL.'
                        : result.urlhaus.message || 'URLhaus did not return a match.'}
                    </div>
                  )}
                </div>
              )}

              {/* ── Vendor analysis ── */}
              {result.vendor_data && (
                <div>
                  <h3 className="text-sm font-semibold text-white mb-3">Security Engine Results</h3>
                  <VendorTable
                    malicious={result.vendor_data.malicious ?? []}
                    suspicious={result.vendor_data.suspicious ?? []}
                    clean={result.vendor_data.clean ?? []}
                    stats={result.vendor_data.stats}
                  />
                </div>
              )}
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </PageWrapper>
  )
}
