import { useState, FormEvent } from 'react'
import { Search, FileCode2, ShieldCheck, ShieldAlert, AlertTriangle, Lock, LockOpen } from 'lucide-react'
import PageWrapper from '../components/ui/PageWrapper'
import LoadingSpinner from '../components/ui/LoadingSpinner'
import { headerAnalysis } from '../lib/api'
import type { HeaderAnalysisResult } from '../types'

function gradeClass(grade: HeaderAnalysisResult['grade']) {
  if (grade === 'A+' || grade === 'A') return 'text-green-400 border-green-500/30 bg-green-500/10'
  if (grade === 'B' || grade === 'C') return 'text-amber-400 border-amber-500/30 bg-amber-500/10'
  return 'text-red-400 border-red-500/30 bg-red-500/10'
}

function headerStatusClass(status: 'Present' | 'Missing' | 'Weak') {
  if (status === 'Present') return 'text-green-400 border-green-500/30 bg-green-500/10'
  if (status === 'Weak') return 'text-amber-400 border-amber-500/30 bg-amber-500/10'
  return 'text-red-400 border-red-500/30 bg-red-500/10'
}

function boolBadge(flag: boolean) {
  return flag ? (
    <span className="inline-flex items-center gap-1 text-green-400">
      <ShieldCheck size={12} /> Yes
    </span>
  ) : (
    <span className="inline-flex items-center gap-1 text-red-400">
      <ShieldAlert size={12} /> No
    </span>
  )
}

export default function HTTPHeaderAnalyzer() {
  const [target, setTarget] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<HeaderAnalysisResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  async function onSubmit(e: FormEvent) {
    e.preventDefault()
    const trimmed = target.trim()
    if (!trimmed) return

    setLoading(true)
    setError(null)
    setResult(null)

    try {
      setResult(await headerAnalysis(trimmed))
    } catch (e) {
      setError(e instanceof Error ? e.message : 'HTTP header audit failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <PageWrapper>
      <div className="max-w-6xl mx-auto px-4 sm:px-6 pt-28 pb-20">
        <div className="mb-8 flex items-center gap-2.5">
          <div className="p-2 rounded-lg bg-[#0d6efd]/10 border border-[#0d6efd]/20">
            <FileCode2 size={18} className="text-[#0d6efd]" />
          </div>
          <h1 className="text-2xl font-bold text-white">Advanced Web Security Header Auditor</h1>
        </div>

        <form onSubmit={onSubmit} className="glass-card rounded-2xl p-5 mb-6">
          <label className="block text-xs font-mono text-gray-400 mb-2 uppercase tracking-wider">Target URL</label>
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
              Audit
            </button>
          </div>
        </form>

        {loading && (
          <div className="glass-card rounded-2xl">
            <LoadingSpinner label="Auditing headers, cookies, redirects, and security posture..." />
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
              <div className="flex items-center justify-between flex-wrap gap-3 mb-3">
                <div>
                  <div className="text-xs text-gray-500 font-mono mb-1">Final URL</div>
                  <div className="text-sm text-gray-200 font-mono break-all">{result.final_url}</div>
                </div>
                <span className={`text-xs px-2.5 py-1 rounded border font-mono ${gradeClass(result.grade)}`}>
                  Grade {result.grade} ({result.score}/100)
                </span>
              </div>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <div className="rounded-xl border border-white/10 bg-white/3 p-3">
                  <div className="text-[10px] text-gray-500 uppercase font-mono">HTTPS</div>
                  <div className="text-sm font-mono mt-1">
                    {result.https_enforced ? (
                      <span className="inline-flex items-center gap-1 text-green-400"><Lock size={13} /> Enabled</span>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-red-400"><LockOpen size={13} /> Not Enforced</span>
                    )}
                  </div>
                </div>
                <div className="rounded-xl border border-white/10 bg-white/3 p-3">
                  <div className="text-[10px] text-gray-500 uppercase font-mono">Missing Headers</div>
                  <div className="text-sm text-white font-mono mt-1">{result.headers_missing.length}</div>
                </div>
                <div className="rounded-xl border border-white/10 bg-white/3 p-3">
                  <div className="text-[10px] text-gray-500 uppercase font-mono">Cookie Risks</div>
                  <div className="text-sm text-white font-mono mt-1">{result.cookie_risk_count}</div>
                </div>
                <div className="rounded-xl border border-white/10 bg-white/3 p-3">
                  <div className="text-[10px] text-gray-500 uppercase font-mono">Response Time</div>
                  <div className="text-sm text-white font-mono mt-1">{result.response_time_ms} ms</div>
                </div>
              </div>
              <div className="mt-3 text-xs text-gray-500 font-mono">
                Status: {result.status_code} | Protocol: {result.protocol_used.toUpperCase()} | Redirects: {Math.max(0, result.redirect_chain.length - 1)}
              </div>
            </div>

            <div className="glass-card rounded-2xl p-5">
              <h3 className="text-sm font-semibold text-white mb-3">Security Headers</h3>
              <div className="overflow-x-auto rounded-xl border border-white/10">
                <table className="w-full min-w-[760px] text-left table-auto">
                  <thead className="bg-white/5">
                    <tr>
                      <th className="px-3 py-2.5 text-xs text-gray-500 font-mono">Header</th>
                      <th className="px-3 py-2.5 text-xs text-gray-500 font-mono">Status</th>
                      <th className="px-3 py-2.5 text-xs text-gray-500 font-mono">Notes</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.security_headers.map((h) => (
                      <tr key={h.header} className="border-t border-white/10">
                        <td className="px-3 py-2.5 text-sm text-gray-200 font-mono">{h.header}</td>
                        <td className="px-3 py-2.5">
                          <span className={`text-xs font-mono px-2 py-1 rounded border ${headerStatusClass(h.status)}`}>
                            {h.status}
                          </span>
                        </td>
                        <td className="px-3 py-2.5 text-sm text-gray-400 font-mono">{h.notes}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="glass-card rounded-2xl p-5">
              <h3 className="text-sm font-semibold text-white mb-3">Response Headers</h3>
              <div className="space-y-1.5 max-h-96 overflow-auto pr-1">
                {Object.entries(result.headers).map(([key, value]) => (
                  <div key={key} className="bg-white/3 rounded-lg px-3 py-2 border border-white/5">
                    <div className="text-xs text-gray-500 font-mono">{key}</div>
                    <div className="text-sm text-gray-200 font-mono break-all">{value}</div>
                  </div>
                ))}
              </div>
            </div>

            <div className="glass-card rounded-2xl p-5">
              <h3 className="text-sm font-semibold text-white mb-3">Cookie Security Audit</h3>
              {result.cookies.length === 0 ? (
                <div className="text-sm text-gray-500 font-mono">No Set-Cookie headers were found.</div>
              ) : (
                <div className="overflow-x-auto rounded-xl border border-white/10">
                  <table className="w-full min-w-[920px] text-left table-auto">
                    <thead className="bg-white/5">
                      <tr>
                        <th className="px-3 py-2.5 text-xs text-gray-500 font-mono">Cookie</th>
                        <th className="px-3 py-2.5 text-xs text-gray-500 font-mono">HttpOnly</th>
                        <th className="px-3 py-2.5 text-xs text-gray-500 font-mono">Secure</th>
                        <th className="px-3 py-2.5 text-xs text-gray-500 font-mono">SameSite</th>
                        <th className="px-3 py-2.5 text-xs text-gray-500 font-mono">Risk</th>
                      </tr>
                    </thead>
                    <tbody>
                      {result.cookies.map((cookie) => (
                        <tr key={cookie.cookie_name} className="border-t border-white/10">
                          <td className="px-3 py-2.5 text-sm text-gray-200 font-mono">{cookie.cookie_name}</td>
                          <td className="px-3 py-2.5 text-sm font-mono">{boolBadge(cookie.httponly)}</td>
                          <td className="px-3 py-2.5 text-sm font-mono">{boolBadge(cookie.secure)}</td>
                          <td className="px-3 py-2.5 text-sm text-gray-300 font-mono">{cookie.samesite}</td>
                          <td className="px-3 py-2.5 text-xs font-mono whitespace-normal break-all">
                            {cookie.risk === 'None' ? (
                              <span className="text-green-400">No immediate risk detected</span>
                            ) : (
                              <span className="text-amber-300">{cookie.risk}</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
              <div className="glass-card rounded-2xl p-5">
                <h3 className="text-sm font-semibold text-white mb-3">Information Leakage</h3>
                {result.leaks.length === 0 ? (
                  <p className="text-sm text-green-400 font-mono">No obvious server/framework disclosure detected.</p>
                ) : (
                  <ul className="space-y-2">
                    {result.leaks.map((leak) => (
                      <li key={leak} className="text-sm text-amber-300 font-mono flex items-start gap-2">
                        <AlertTriangle size={14} className="mt-0.5 shrink-0" />
                        <span>{leak}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>

              <div className="glass-card rounded-2xl p-5">
                <h3 className="text-sm font-semibold text-white mb-3">Recommendations</h3>
                {result.recommendations.length === 0 ? (
                  <p className="text-sm text-green-400 font-mono">No critical remediation items.</p>
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
