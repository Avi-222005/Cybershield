import { useState, FormEvent } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Wifi,
  Search,
  Info,
  MapPin,
  Building2,
  Network,
  Clock,
  AlertTriangle,
  Tag,
  CheckCircle2,
  XCircle,
} from 'lucide-react'
import PageWrapper from '../components/ui/PageWrapper'
import ResultBadge from '../components/ui/ResultBadge'
import ScoreGauge from '../components/ui/ScoreGauge'
import VendorTable from '../components/ui/VendorTable'
import LoadingSpinner from '../components/ui/LoadingSpinner'
import { checkIp } from '../lib/api'
import { getSeverityColor } from '../lib/utils'
import type { IPResult } from '../types'

const severityBadge: Record<string, string> = {
  low: 'text-green-400 bg-green-500/10 border-green-500/25',
  medium: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/25',
  high: 'text-orange-400 bg-orange-500/10 border-orange-500/25',
  critical: 'text-red-400 bg-red-500/10 border-red-500/25',
}

function hasValidCoordinates(latitude: number | null, longitude: number | null): boolean {
  return (
    typeof latitude === 'number' &&
    typeof longitude === 'number' &&
    Number.isFinite(latitude) &&
    Number.isFinite(longitude)
  )
}

function getOpenStreetMapEmbedUrl(latitude: number, longitude: number): string {
  const delta = 0.05
  const minLon = longitude - delta
  const minLat = latitude - delta
  const maxLon = longitude + delta
  const maxLat = latitude + delta

  return `https://www.openstreetmap.org/export/embed.html?bbox=${minLon}%2C${minLat}%2C${maxLon}%2C${maxLat}&layer=mapnik&marker=${latitude}%2C${longitude}`
}

function getOpenStreetMapViewUrl(latitude: number, longitude: number): string {
  return `https://www.openstreetmap.org/?mlat=${latitude}&mlon=${longitude}#map=12/${latitude}/${longitude}`
}

function splitRecommendation(text: string): string[] {
  const normalized = text.replace(/\s+/g, ' ').trim()
  if (!normalized) return []

  const bulletParts = normalized
    .split('•')
    .map((part) => part.trim())
    .filter(Boolean)

  if (bulletParts.length > 1) return bulletParts

  const numberedParts = normalized
    .split(/(?=\d+\.\s)/)
    .map((part) => part.trim())
    .filter(Boolean)

  return numberedParts.length > 1 ? numberedParts : [normalized]
}

function hasRiskFactor(
  result: IPResult,
  indicators: string[],
): { detected: boolean; description: string | null; riskPoints: number } {
  const factor = result.risk_factors?.find((rf) => indicators.includes(rf.indicator))
  if (!factor) return { detected: false, description: null, riskPoints: 0 }
  return { detected: true, description: factor.description, riskPoints: factor.risk_points ?? 0 }
}

export default function IPChecker() {
  const [ip, setIp] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<IPResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    const trimmed = ip.trim()
    if (!trimmed) return

    setLoading(true)
    setResult(null)
    setError(null)

    try {
      const data = await checkIp(trimmed)
      setResult(data)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Analysis failed. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <PageWrapper>
      <div className="max-w-4xl mx-auto px-4 sm:px-6 pt-28 pb-20">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-2.5 mb-2">
            <div className="p-2 rounded-lg bg-[#0d6efd]/10 border border-[#0d6efd]/20">
              <Wifi size={18} className="text-[#0d6efd]" />
            </div>
            <h1 className="text-2xl font-bold text-white">IP Reputation Checker</h1>
          </div>
          <p className="text-gray-500 text-sm ml-10">
            Geolocation · VPN/Proxy detection · Multi-vendor threat intelligence
          </p>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="glass-card rounded-2xl p-5 mb-6">
          <label className="block text-xs font-mono text-gray-400 mb-2 uppercase tracking-wider">
            IP Address (IPv4 or IPv6)
          </label>
          <div className="flex gap-3">
            <input
              type="text"
              value={ip}
              onChange={(e) => setIp(e.target.value)}
              placeholder="8.8.8.8 or 2001:4860:4860::8888"
              className="cyber-input flex-1 px-4 py-3 rounded-xl text-sm font-mono"
              required
              disabled={loading}
            />
            <button
              type="submit"
              disabled={loading || !ip.trim()}
              className="flex items-center gap-2 px-6 py-3 bg-[#0d6efd] hover:bg-[#0b5ed7] disabled:opacity-50 disabled:cursor-not-allowed !text-white font-semibold rounded-xl transition-colors text-sm shrink-0"
            >
              <Search size={16} />
              Analyze
            </button>
          </div>
          <p className="text-xs text-gray-600 mt-2.5">
            <Info size={11} className="inline mr-1" />
            Private, loopback, reserved, and multicast IPs are not analyzed.
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
              <LoadingSpinner label="Fetching threat intelligence & geolocation…" />
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
              {/* ── Verdict + score ── */}
              <div className="glass-card rounded-2xl p-6">
                <div className="flex flex-col sm:flex-row items-start sm:items-center gap-6">
                  <div className="shrink-0">
                    <ScoreGauge score={result.final_score} />
                  </div>
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
                      <span className="text-xs px-2.5 py-1 rounded-full border border-white/10 text-gray-400 font-mono">
                        {result.ip_version ?? 'IPv4'}
                      </span>
                    </div>
                    <div className="mb-4">
                      <ul className="space-y-1.5">
                        {splitRecommendation(result.security_recommendation).map((line, index) => (
                          <li key={index} className="text-sm text-gray-300 leading-relaxed flex items-start gap-2">
                            <span className="text-[#0d6efd] mt-1 text-xs">•</span>
                            <span>{line}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                    <div className="grid grid-cols-2 gap-3">
                      <div className="bg-white/3 rounded-lg px-3 py-2.5">
                        <div className="text-xs text-gray-500 font-mono mb-0.5">Custom Analysis</div>
                        <div className="text-lg font-bold font-mono text-[#0d6efd]">
                          {result.custom_score}<span className="text-xs text-gray-500">/100</span>
                        </div>
                        <div className="text-xs text-gray-600">40% weight</div>
                      </div>
                      <div className="bg-white/3 rounded-lg px-3 py-2.5">
                        <div className="text-xs text-gray-500 font-mono mb-0.5">API Intelligence</div>
                        <div className="text-lg font-bold font-mono text-blue-400">
                          {result.api_score}<span className="text-xs text-gray-500">/70</span>
                        </div>
                        <div className="text-xs text-gray-600">60% weight</div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              {/* ── Custom Analysis Indicators (5 indicators) ── */}
              <div className="glass-card rounded-2xl p-5">
                <h3 className="text-sm font-semibold text-white mb-4">
                  Custom Analysis Indicators
                  <span className="ml-2 text-xs text-gray-500 font-mono font-normal">
                    (5 security parameters)
                  </span>
                </h3>

                {(() => {
                  const hosting = hasRiskFactor(result, ['Hosting Provider'])
                  const vpnProxy = hasRiskFactor(result, ['VPN/Proxy/Anonymizer', 'Anonymous Connection'])
                  const unknownLocation = hasRiskFactor(result, ['Unknown Location'])
                  const unknownIsp = hasRiskFactor(result, ['Unknown ISP'])
                  const unusualConnection = hasRiskFactor(result, ['Unusual Connection'])

                  const indicators = [
                    {
                      id: 1,
                      name: 'Hosting Provider',
                      weight: 15,
                      triggered: hosting.detected,
                      value: result.isp || 'N/A',
                      threshold: 'Cloud/VPS provider pattern in ISP',
                      description: hosting.description || 'No high-risk hosting-provider pattern detected',
                      riskPoints: hosting.riskPoints,
                    },
                    {
                      id: 2,
                      name: 'VPN/Proxy/Tor',
                      weight: 30,
                      triggered: vpnProxy.detected,
                      value: result.connection_type || result.isp || 'N/A',
                      threshold: 'VPN/Proxy/Anonymizer keyword match',
                      description: vpnProxy.description || 'No VPN/proxy/anonymizer indicators found',
                      riskPoints: vpnProxy.riskPoints,
                    },
                    {
                      id: 3,
                      name: 'Unknown Location',
                      weight: 10,
                      triggered: unknownLocation.detected,
                      value: `${result.country || 'N/A'}${result.city && result.city !== 'N/A' ? `, ${result.city}` : ''}`,
                      threshold: 'Country unavailable/unknown',
                      description: unknownLocation.description || 'Location data appears available',
                      riskPoints: unknownLocation.riskPoints,
                    },
                    {
                      id: 4,
                      name: 'Unknown ISP',
                      weight: 5,
                      triggered: unknownIsp.detected,
                      value: result.isp || 'N/A',
                      threshold: 'ISP unavailable/unknown pattern',
                      description: unknownIsp.description || 'ISP information looks available',
                      riskPoints: unknownIsp.riskPoints,
                    },
                    {
                      id: 5,
                      name: 'Unusual Connection',
                      weight: 5,
                      triggered: unusualConnection.detected,
                      value: result.connection_type || 'N/A',
                      threshold: 'Dial-up/satellite or uncommon type',
                      description: unusualConnection.description || 'No unusual connection type detected',
                      riskPoints: unusualConnection.riskPoints,
                    },
                  ]

                  return (
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                      {indicators.map((ind) => (
                        <div
                          key={ind.id}
                          className={`rounded-xl border p-3 ${
                            ind.triggered
                              ? 'bg-red-500/10 border-red-500/30'
                              : 'bg-green-500/10 border-green-500/30'
                          }`}
                        >
                          <div className="flex items-start justify-between gap-2 mb-2">
                            <div>
                              <div className="text-xs font-semibold text-white">
                                #{ind.id} {ind.name}
                              </div>
                              <div className="text-[10px] text-gray-400 font-mono">Weight: {ind.weight}%</div>
                            </div>
                            {ind.triggered ? (
                              <XCircle size={16} className="text-red-400 shrink-0" />
                            ) : (
                              <CheckCircle2 size={16} className="text-green-400 shrink-0" />
                            )}
                          </div>

                          <div className="text-[11px] font-mono text-gray-300 truncate mb-1">{ind.value}</div>
                          <div className="text-[10px] text-gray-500 mb-1">{ind.description}</div>
                          <div className="text-[9px] text-gray-600 font-mono">
                            Threshold: {ind.threshold} {ind.triggered ? `• +${ind.riskPoints} pts` : '• +0 pts'}
                          </div>
                        </div>
                      ))}
                    </div>
                  )
                })()}
              </div>

              {/* ── Geolocation ── */}
              <div className="glass-card rounded-2xl p-5">
                <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
                  <MapPin size={15} className="text-[#0d6efd]" />
                  Geolocation
                </h3>
                <div className="grid sm:grid-cols-2 gap-3">
                  {[
                    { label: 'Country', value: result.country, icon: MapPin },
                    { label: 'Region', value: result.region, icon: MapPin },
                    { label: 'City', value: result.city, icon: MapPin },
                    { label: 'ISP', value: result.isp, icon: Building2 },
                    { label: 'ASN', value: result.asn, icon: Network },
                    { label: 'Timezone', value: result.timezone, icon: Clock },
                    { label: 'Connection Type', value: result.connection_type, icon: Wifi },
                    { label: 'Postal Code', value: result.postal_code, icon: MapPin },
                  ].map(({ label, value, icon: Icon }) =>
                    value && value !== 'N/A' && value !== 'Unavailable' ? (
                      <div key={label} className="bg-white/3 rounded-lg px-3 py-2.5 flex items-start gap-2">
                        <Icon size={13} className="text-gray-500 mt-0.5 shrink-0" />
                        <div>
                          <div className="text-xs text-gray-500 font-mono">{label}</div>
                          <div className="text-sm text-gray-200">{value}</div>
                        </div>
                      </div>
                    ) : null,
                  )}
                </div>

                {hasValidCoordinates(result.latitude, result.longitude) && (
                  <div className="mt-4">
                    <div className="text-xs text-gray-500 font-mono mb-2">Map Location</div>
                    <div className="rounded-xl overflow-hidden border border-white/10 bg-black/20">
                      <iframe
                        title="IP geolocation map"
                        src={getOpenStreetMapEmbedUrl(result.latitude, result.longitude)}
                        className="w-full h-72"
                        loading="lazy"
                        referrerPolicy="no-referrer-when-downgrade"
                      />
                    </div>
                    <a
                      href={getOpenStreetMapViewUrl(result.latitude, result.longitude)}
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex mt-2 text-xs text-[#0d6efd] hover:text-blue-300 font-mono"
                    >
                      Open in OpenStreetMap
                    </a>
                  </div>
                )}
              </div>

              {/* ── Threat categories ── */}
              {result.threat_categories?.length > 0 && (
                <div className="glass-card rounded-2xl p-5">
                  <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
                    <Tag size={15} className="text-red-400" />
                    Threat Categories
                  </h3>
                  <div className="flex flex-wrap gap-2">
                    {result.threat_categories.map((cat) => (
                      <span
                        key={cat}
                        className="text-xs px-3 py-1.5 rounded-full bg-red-500/10 border border-red-500/20 text-red-400 font-mono"
                      >
                        {cat}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* ── Risk factors ── */}
              {result.risk_factors?.length > 0 && (
                <div className="glass-card rounded-2xl p-5">
                  <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
                    <AlertTriangle size={15} className="text-yellow-400" />
                    Risk Factors
                  </h3>
                  <div className="space-y-2">
                    {result.risk_factors.map((rf, i) => (
                      <div
                        key={i}
                        className="flex items-start gap-3 px-3 py-2.5 rounded-lg bg-white/3 border border-white/5"
                      >
                        <span
                          className={`text-[10px] px-1.5 py-0.5 rounded font-mono border mt-0.5 shrink-0 ${
                            severityBadge[rf.severity?.toLowerCase()] ?? severityBadge.medium
                          }`}
                        >
                          {rf.severity}
                        </span>
                        <div>
                          <div className="text-xs font-semibold text-gray-300">{rf.indicator}</div>
                          <div className="text-xs text-gray-500 mt-0.5">{rf.description}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* ── Vendor analysis ── */}
              {result.vendor_data && (
                <div>
                  <h3 className="text-sm font-semibold text-white mb-3">Security Engine Results</h3>
                  <VendorTable
                    malicious={result.vendor_data.malicious_vendors ?? []}
                    suspicious={result.vendor_data.suspicious_vendors ?? []}
                    clean={result.vendor_data.clean_vendors ?? []}
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
