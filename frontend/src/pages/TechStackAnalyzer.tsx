import { FormEvent, type ElementType, useMemo, useState } from 'react'
import {
  Brain,
  Cloud,
  Cpu,
  Newspaper,
  Palette,
  Search,
  Server,
  Shield,
  ShieldCheck,
} from 'lucide-react'
import PageWrapper from '../components/ui/PageWrapper'
import LoadingSpinner from '../components/ui/LoadingSpinner'
import { techStackAnalysis } from '../lib/api'
import type { TechStackDetectedTechnology, TechStackResult } from '../types'

const SECTION_ORDER = [
  'Frontend',
  'Backend',
  'CMS',
  'Server',
  'Security',
  'Analytics',
  'Hosting',
  'Payment',
  'Other',
]

const sectionIcon: Record<string, ElementType> = {
  Frontend: Palette,
  Backend: Cpu,
  CMS: Newspaper,
  Server: Server,
  Security: Shield,
  Analytics: Brain,
  Hosting: Cloud,
  Payment: ShieldCheck,
  Other: Brain,
}

function confidenceTone(confidence: number): string {
  if (confidence >= 85) return 'text-green-300 border-green-500/35 bg-green-500/10'
  if (confidence >= 60) return 'text-amber-300 border-amber-500/35 bg-amber-500/10'
  return 'text-orange-300 border-orange-500/35 bg-orange-500/10'
}

export default function TechStackAnalyzer() {
  const [target, setTarget] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<TechStackResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  const groupedSections = useMemo(() => {
    if (!result?.grouped) return []

    return SECTION_ORDER
      .filter((section) => (result.grouped[section] || []).length > 0)
      .map((section) => ({
        section,
        rows: result.grouped[section],
      }))
  }, [result])

  async function onSubmit(e: FormEvent) {
    e.preventDefault()
    if (!target.trim()) return

    setLoading(true)
    setError(null)
    setResult(null)

    try {
      setResult(await techStackAnalysis(target.trim()))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Tech stack analysis failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <PageWrapper>
      <div className="max-w-7xl mx-auto px-4 sm:px-6 pt-28 pb-20">
        <div className="mb-8">
          <div className="flex items-center gap-2.5 mb-2">
            <div className="p-2 rounded-lg bg-[#0d6efd]/10 border border-[#0d6efd]/20">
              <Brain size={18} className="text-[#0d6efd]" />
            </div>
            <h1 className="text-2xl font-bold text-white">Tech Stack Detector</h1>
          </div>
          <p className="text-gray-500 text-sm ml-10">
            Wappalyzer-style fingerprinting with version extraction, confidence scoring, and category intelligence.
          </p>
        </div>

        <form onSubmit={onSubmit} className="glass-card rounded-2xl p-5 mb-6">
          <div className="flex gap-3">
            <input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="example.com or https://example.com"
              className="cyber-input flex-1 px-4 py-3 rounded-xl text-sm font-mono"
              disabled={loading}
            />
            <button
              disabled={loading || !target.trim()}
              className="flex items-center gap-2 px-6 py-3 bg-[#0d6efd] hover:bg-[#0b5ed7] disabled:opacity-50 disabled:cursor-not-allowed !text-white font-semibold rounded-xl text-sm"
            >
              <Search size={16} />
              Detect
            </button>
          </div>
        </form>

        {loading && (
          <div className="glass-card rounded-2xl">
            <LoadingSpinner label="Fingerprinting technologies from headers, source, scripts, DNS, cookies, and metadata..." />
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
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <h2 className="text-lg font-semibold text-white">Detection Summary</h2>
                  <div className="text-xs text-gray-500 font-mono mt-1 break-all">
                    Target: {result.target} | Final URL: {result.url}
                    {result.cached ? ' | CACHE HIT' : ''}
                  </div>
                </div>
                <div className="text-xs font-mono text-gray-300 rounded-lg border border-white/10 bg-white/5 px-3 py-2">
                  {result.summary.total} detections | {result.summary.high_confidence} high confidence
                </div>
              </div>

              <div className="grid sm:grid-cols-3 gap-3 mt-4">
                <div className="rounded-lg border border-white/10 bg-white/3 px-3 py-2">
                  <div className="text-[10px] text-gray-500 font-mono uppercase">Frameworks</div>
                  <div className="text-sm text-gray-200 font-mono mt-1">
                    {result.summary.frameworks.length > 0 ? result.summary.frameworks.slice(0, 5).join(', ') : 'None'}
                  </div>
                </div>
                <div className="rounded-lg border border-white/10 bg-white/3 px-3 py-2">
                  <div className="text-[10px] text-gray-500 font-mono uppercase">Servers</div>
                  <div className="text-sm text-gray-200 font-mono mt-1">
                    {result.summary.servers.length > 0 ? result.summary.servers.slice(0, 5).join(', ') : 'None'}
                  </div>
                </div>
                <div className="rounded-lg border border-white/10 bg-white/3 px-3 py-2">
                  <div className="text-[10px] text-gray-500 font-mono uppercase">Security</div>
                  <div className="text-sm text-gray-200 font-mono mt-1">
                    {result.summary.security.length > 0 ? result.summary.security.slice(0, 5).join(', ') : 'None'}
                  </div>
                </div>
              </div>
            </div>

            {groupedSections.length === 0 ? (
              <div className="glass-card rounded-2xl p-5 text-sm text-gray-400 font-mono">
                No technologies detected above confidence threshold.
              </div>
            ) : (
              <div className="space-y-4">
                {groupedSections.map(({ section, rows }) => {
                  const Icon = sectionIcon[section] || Brain
                  return (
                    <div key={section} className="glass-card rounded-2xl p-5">
                      <div className="flex items-center gap-2 mb-3">
                        <Icon size={16} className="text-[#6ea8fe]" />
                        <h3 className="text-sm font-semibold text-white">{section}</h3>
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-white/15 text-gray-300 bg-white/5">
                          {rows.length}
                        </span>
                      </div>

                      <div className="grid md:grid-cols-2 xl:grid-cols-3 gap-3">
                        {rows.map((item: TechStackDetectedTechnology) => (
                          <div key={`${section}-${item.name}`} className="rounded-xl border border-white/10 bg-white/3 p-3">
                            <div className="flex items-start justify-between gap-2">
                              <div>
                                <div className="text-sm text-gray-100 font-semibold">{item.name}</div>
                                <div className="text-[11px] text-gray-500 font-mono mt-0.5">
                                  {item.normalized_name || item.name}
                                </div>
                              </div>
                              <span className={`text-[10px] px-2 py-0.5 rounded border font-mono ${confidenceTone(item.confidence)}`}>
                                {item.confidence}%
                              </span>
                            </div>

                            <div className="mt-2 text-xs text-gray-300 font-mono">
                              Version: {item.version || 'Unknown'}
                            </div>

                            <div className="mt-2 flex flex-wrap gap-1.5">
                              {(item.categories || []).slice(0, 4).map((category) => (
                                <span
                                  key={`${item.name}-${category}`}
                                  className="text-[10px] px-2 py-0.5 rounded border border-white/15 text-gray-300 bg-white/5 font-mono"
                                >
                                  {category}
                                </span>
                              ))}
                            </div>

                            {item.website && (
                              <a
                                href={item.website}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="mt-2 inline-block text-[11px] text-[#6ea8fe] hover:text-[#9ec5fe] font-mono"
                              >
                                {item.website}
                              </a>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        )}
      </div>
    </PageWrapper>
  )
}
