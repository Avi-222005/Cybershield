import { useState, FormEvent } from 'react'
import { Search, FileCode2 } from 'lucide-react'
import PageWrapper from '../components/ui/PageWrapper'
import LoadingSpinner from '../components/ui/LoadingSpinner'
import { headerAnalysis } from '../lib/api'
import type { HeaderAnalysisResult } from '../types'

export default function HTTPHeaderAnalyzer() {
  const [url, setUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<HeaderAnalysisResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  async function onSubmit(e: FormEvent) {
    e.preventDefault()
    if (!url.trim()) return
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      setResult(await headerAnalysis(url.trim()))
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Header analysis failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <PageWrapper>
      <div className="max-w-4xl mx-auto px-4 sm:px-6 pt-28 pb-20">
        <div className="mb-8 flex items-center gap-2.5">
          <div className="p-2 rounded-lg bg-[#0d6efd]/10 border border-[#0d6efd]/20">
            <FileCode2 size={18} className="text-[#0d6efd]" />
          </div>
          <h1 className="text-2xl font-bold text-white">HTTP Header Analyzer</h1>
        </div>

        <form onSubmit={onSubmit} className="glass-card rounded-2xl p-5 mb-6">
          <div className="flex gap-3">
            <input
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example.com"
              className="cyber-input flex-1 px-4 py-3 rounded-xl text-sm font-mono"
            />
            <button className="flex items-center gap-2 px-6 py-3 bg-[#0d6efd] hover:bg-[#0b5ed7] !text-white font-semibold rounded-xl text-sm">
              <Search size={16} />
              Analyze
            </button>
          </div>
        </form>

        {loading && <div className="glass-card rounded-2xl"><LoadingSpinner label="Fetching HTTP headers..." /></div>}
        {error && <div className="glass-card rounded-2xl p-5 border border-red-500/25 bg-red-500/5 text-red-400 text-sm font-mono">{error}</div>}

        {result && (
          <div className="space-y-5">
            <div className="glass-card rounded-2xl p-5">
              <div className="text-xs text-gray-500 font-mono mb-2">URL</div>
              <div className="text-sm text-gray-200 font-mono break-all">{result.url}</div>
              <div className="text-xs text-gray-500 font-mono mt-3">Status Code: {result.status_code}</div>
            </div>

            <div className="glass-card rounded-2xl p-5">
              <h3 className="text-sm font-semibold text-white mb-3">Missing Security Headers</h3>
              {result.missing_security_headers.length > 0 ? (
                <div className="flex flex-wrap gap-2">
                  {result.missing_security_headers.map((h) => (
                    <span key={h} className="text-xs px-2.5 py-1 rounded-full border border-red-500/30 bg-red-500/10 text-red-400 font-mono">
                      {h}
                    </span>
                  ))}
                </div>
              ) : (
                <div className="text-sm text-green-400 font-mono">All required security headers are present.</div>
              )}
            </div>

            <div className="glass-card rounded-2xl p-5">
              <h3 className="text-sm font-semibold text-white mb-3">Response Headers</h3>
              <div className="space-y-1.5 max-h-96 overflow-auto pr-1">
                {Object.entries(result.headers).map(([key, value]) => (
                  <div key={key} className="bg-white/3 rounded-lg px-3 py-2">
                    <div className="text-xs text-gray-500 font-mono">{key}</div>
                    <div className="text-sm text-gray-200 font-mono break-all">{value}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </PageWrapper>
  )
}
