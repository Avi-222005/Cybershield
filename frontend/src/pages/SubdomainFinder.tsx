import { useState, FormEvent } from 'react'
import { Search, Network } from 'lucide-react'
import PageWrapper from '../components/ui/PageWrapper'
import LoadingSpinner from '../components/ui/LoadingSpinner'
import { subdomainScan } from '../lib/api'
import type { SubdomainScanResult } from '../types'

export default function SubdomainFinder() {
  const [domain, setDomain] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<SubdomainScanResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  async function onSubmit(e: FormEvent) {
    e.preventDefault()
    if (!domain.trim()) return
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      setResult(await subdomainScan(domain.trim()))
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Subdomain scan failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <PageWrapper>
      <div className="max-w-4xl mx-auto px-4 sm:px-6 pt-28 pb-20">
        <div className="mb-8 flex items-center gap-2.5">
          <div className="p-2 rounded-lg bg-[#0d6efd]/10 border border-[#0d6efd]/20">
            <Network size={18} className="text-[#0d6efd]" />
          </div>
          <h1 className="text-2xl font-bold text-white">Subdomain Finder</h1>
        </div>

        <form onSubmit={onSubmit} className="glass-card rounded-2xl p-5 mb-6">
          <div className="flex gap-3">
            <input
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="example.com"
              className="cyber-input flex-1 px-4 py-3 rounded-xl text-sm font-mono"
            />
            <button className="flex items-center gap-2 px-6 py-3 bg-[#0d6efd] hover:bg-[#0b5ed7] !text-white font-semibold rounded-xl text-sm">
              <Search size={16} />
              Scan
            </button>
          </div>
        </form>

        {loading && <div className="glass-card rounded-2xl"><LoadingSpinner label="Discovering subdomains..." /></div>}
        {error && <div className="glass-card rounded-2xl p-5 border border-red-500/25 bg-red-500/5 text-red-400 text-sm font-mono">{error}</div>}

        {result && (
          <div className="glass-card rounded-2xl p-5">
            <div className="text-sm text-gray-400 font-mono mb-3">Found: {result.count}</div>
            <div className="space-y-2">
              {result.found.length > 0 ? (
                result.found.map((entry) => (
                  <div key={entry.subdomain} className="bg-white/3 rounded-lg px-3 py-2">
                    <div className="text-sm text-gray-200 font-mono">{entry.subdomain}</div>
                    <div className="text-xs text-gray-500 font-mono">{entry.ip}</div>
                  </div>
                ))
              ) : (
                <div className="text-sm text-gray-500 font-mono bg-white/3 rounded-lg px-3 py-2">No subdomains discovered</div>
              )}
            </div>
          </div>
        )}
      </div>
    </PageWrapper>
  )
}
