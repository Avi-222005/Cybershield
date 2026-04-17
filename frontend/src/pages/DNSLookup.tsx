import { useMemo, useState, FormEvent } from 'react'
import { Search, Globe2, ShieldCheck, ShieldAlert, Mail, Network } from 'lucide-react'
import PageWrapper from '../components/ui/PageWrapper'
import LoadingSpinner from '../components/ui/LoadingSpinner'
import { dnsLookupPro } from '../lib/api'
import type { DNSLookupProResult } from '../types'

type TabKey = 'A' | 'AAAA' | 'CNAME' | 'MX' | 'NS' | 'TXT' | 'SOA' | 'CAA'

const RECORD_TABS: TabKey[] = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'CAA']

function gradeClass(grade: DNSLookupProResult['grade']) {
  if (grade === 'A+' || grade === 'A') return 'text-green-400 border-green-500/30 bg-green-500/10'
  if (grade === 'B' || grade === 'C') return 'text-amber-400 border-amber-500/30 bg-amber-500/10'
  return 'text-red-400 border-red-500/30 bg-red-500/10'
}

export default function DNSLookup() {
  const [target, setTarget] = useState('')
  const [activeTab, setActiveTab] = useState<TabKey>('A')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<DNSLookupProResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  const dmarcWeak = useMemo(() => result?.dmarc.policy === 'none' || !result?.dmarc.present, [result])

  async function onSubmit(e: FormEvent) {
    e.preventDefault()
    const trimmed = target.trim()
    if (!trimmed) return

    setLoading(true)
    setError(null)
    setResult(null)

    try {
      const data = await dnsLookupPro(trimmed)
      setResult(data)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'DNS Lookup Pro failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <PageWrapper>
      <div className="max-w-6xl mx-auto px-4 sm:px-6 pt-28 pb-20">
        <div className="mb-8">
          <div className="flex items-center gap-2.5 mb-2">
            <div className="p-2 rounded-lg bg-[#0d6efd]/10 border border-[#0d6efd]/20">
              <Globe2 size={18} className="text-[#0d6efd]" />
            </div>
            <h1 className="text-2xl font-bold text-white">DNS Lookup Pro</h1>
          </div>
          <p className="text-gray-500 text-sm ml-10">
            Advanced DNS security posture audit with grading, email authentication checks, and actionable remediation guidance.
          </p>
        </div>

        <form onSubmit={onSubmit} className="glass-card rounded-2xl p-5 mb-6">
          <label className="block text-xs font-mono text-gray-400 mb-2 uppercase tracking-wider">Target Domain</label>
          <div className="flex gap-3">
            <input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="example.com or sub.example.com"
              className="cyber-input flex-1 px-4 py-3 rounded-xl text-sm font-mono"
              disabled={loading}
            />
            <button
              disabled={loading || !target.trim()}
              className="flex items-center gap-2 px-6 py-3 bg-[#0d6efd] hover:bg-[#0b5ed7] disabled:opacity-50 disabled:cursor-not-allowed !text-white font-semibold rounded-xl text-sm"
            >
              <Search size={16} />
              Lookup Pro
            </button>
          </div>
        </form>

        {loading && (
          <div className="glass-card rounded-2xl">
            <LoadingSpinner label="Collecting DNS records and auditing security posture..." />
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
              <div className="flex flex-wrap items-center justify-between gap-3 mb-3">
                <div>
                  <div className="text-xs text-gray-500 font-mono">Root Domain</div>
                  <div className="text-sm text-gray-200 font-mono break-all">{result.root_domain}</div>
                </div>
                <span className={`text-xs font-mono px-2.5 py-1 rounded border ${gradeClass(result.grade)}`}>
                  Grade {result.grade} ({result.score}/100)
                </span>
              </div>

              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <div className="rounded-xl border border-white/10 bg-white/3 p-3">
                  <div className="text-[10px] text-gray-500 uppercase font-mono">DNSSEC</div>
                  <div className="text-sm font-mono mt-1">
                    {result.dnssec.enabled ? (
                      <span className="inline-flex items-center gap-1 text-green-400"><ShieldCheck size={13} /> Enabled</span>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-red-400"><ShieldAlert size={13} /> Disabled</span>
                    )}
                  </div>
                </div>
                <div className="rounded-xl border border-white/10 bg-white/3 p-3">
                  <div className="text-[10px] text-gray-500 uppercase font-mono">SPF</div>
                  <div className="text-sm font-mono mt-1 text-gray-200">{result.spf.present ? `Present (${result.spf.policy})` : 'Missing'}</div>
                </div>
                <div className="rounded-xl border border-white/10 bg-white/3 p-3">
                  <div className="text-[10px] text-gray-500 uppercase font-mono">DMARC</div>
                  <div className={`text-sm font-mono mt-1 ${dmarcWeak ? 'text-amber-300' : 'text-green-400'}`}>
                    {result.dmarc.present ? `Policy ${result.dmarc.policy}` : 'Missing'}
                  </div>
                </div>
                <div className="rounded-xl border border-white/10 bg-white/3 p-3">
                  <div className="text-[10px] text-gray-500 uppercase font-mono">Infrastructure</div>
                  <div className="text-sm font-mono mt-1 text-gray-200">{result.infrastructure.provider_guess}</div>
                </div>
              </div>
            </div>

            <div className="glass-card rounded-2xl p-5">
              <h3 className="text-sm font-semibold text-white mb-3">DNS Records</h3>
              <div className="flex flex-wrap gap-2 mb-4">
                {RECORD_TABS.map((tab) => (
                  <button
                    key={tab}
                    onClick={() => setActiveTab(tab)}
                    type="button"
                    className={`text-xs font-mono px-3 py-1.5 rounded-lg border transition-colors ${
                      activeTab === tab
                        ? 'text-[#6ea8fe] border-[#0d6efd]/40 bg-[#0d6efd]/15'
                        : 'text-gray-400 border-white/10 bg-white/3 hover:text-gray-200'
                    }`}
                  >
                    {tab}
                  </button>
                ))}
              </div>
              <div className="space-y-1.5 max-h-80 overflow-auto pr-1">
                {(result.records[activeTab] || []).length > 0 ? (
                  result.records[activeTab].map((row, i) => (
                    <div key={`${activeTab}-${i}`} className="bg-white/3 rounded-lg px-3 py-2 border border-white/5 text-sm text-gray-200 font-mono break-all">
                      {row}
                    </div>
                  ))
                ) : (
                  <div className="bg-white/3 rounded-lg px-3 py-2 border border-white/5 text-sm text-gray-500 font-mono">No record found</div>
                )}
              </div>
            </div>

            <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
              <div className="glass-card rounded-2xl p-5">
                <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
                  <Mail size={14} className="text-[#0d6efd]" /> Email Security
                </h3>
                <div className="space-y-3 text-sm font-mono">
                  <div className="bg-white/3 rounded-lg px-3 py-2 border border-white/5">
                    <span className="text-gray-500">SPF:</span>{' '}
                    <span className={result.spf.present ? 'text-green-400' : 'text-red-400'}>
                      {result.spf.present ? `Present (${result.spf.policy})` : 'Missing'}
                    </span>
                  </div>
                  <div className="bg-white/3 rounded-lg px-3 py-2 border border-white/5">
                    <span className="text-gray-500">DMARC:</span>{' '}
                    <span className={result.dmarc.policy === 'reject' ? 'text-green-400' : 'text-amber-300'}>
                      {result.dmarc.present ? `Policy ${result.dmarc.policy}` : 'Missing'}
                    </span>
                  </div>
                  <div className="bg-white/3 rounded-lg px-3 py-2 border border-white/5">
                    <span className="text-gray-500">DKIM:</span>{' '}
                    <span className={result.dkim.status.startsWith('Likely') ? 'text-green-400' : 'text-amber-300'}>{result.dkim.status}</span>
                  </div>
                  <div className="bg-white/3 rounded-lg px-3 py-2 border border-white/5">
                    <span className="text-gray-500">MX:</span>{' '}
                    <span className="text-gray-200">{result.mx.count} records ({result.mx.providers.join(', ') || 'N/A'})</span>
                  </div>
                </div>
              </div>

              <div className="glass-card rounded-2xl p-5">
                <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
                  <Network size={14} className="text-[#0d6efd]" /> Infrastructure
                </h3>
                <div className="space-y-3 text-sm font-mono">
                  <div className="bg-white/3 rounded-lg px-3 py-2 border border-white/5 text-gray-200">
                    Provider Guess: {result.infrastructure.provider_guess}
                  </div>
                  <div className="bg-white/3 rounded-lg px-3 py-2 border border-white/5 text-gray-200">
                    NS Count: {result.ns.count} | A: {result.infrastructure.a_count} | AAAA: {result.infrastructure.aaaa_count}
                  </div>
                  <div className="bg-white/3 rounded-lg px-3 py-2 border border-white/5 text-gray-200">
                    CAA: {result.caa.present ? `${result.caa.authorized_cas.join(', ') || 'Configured'}` : 'Missing'}
                  </div>
                </div>
              </div>
            </div>

            <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
              <div className="glass-card rounded-2xl p-5">
                <h3 className="text-sm font-semibold text-white mb-3">Risks</h3>
                {result.issues.length === 0 ? (
                  <p className="text-sm text-green-400 font-mono">No major DNS misconfiguration detected.</p>
                ) : (
                  <ul className="space-y-2">
                    {result.issues.map((issue) => (
                      <li key={issue} className="text-sm text-amber-300 font-mono flex items-start gap-2">
                        <ShieldAlert size={14} className="mt-0.5 shrink-0" />
                        <span>{issue}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>

              <div className="glass-card rounded-2xl p-5">
                <h3 className="text-sm font-semibold text-white mb-3">Recommendations</h3>
                {result.recommendations.length === 0 ? (
                  <p className="text-sm text-green-400 font-mono">No remediation suggestions right now.</p>
                ) : (
                  <ul className="space-y-2">
                    {result.recommendations.map((rec) => (
                      <li key={rec} className="text-sm text-gray-300 font-mono flex items-start gap-2">
                        <ShieldCheck size={14} className="mt-0.5 shrink-0 text-[#0d6efd]" />
                        <span>{rec}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </PageWrapper>
  )
}
