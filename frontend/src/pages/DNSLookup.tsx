import { useState, FormEvent } from 'react'
import { Search, Globe2, Info } from 'lucide-react'
import PageWrapper from '../components/ui/PageWrapper'
import LoadingSpinner from '../components/ui/LoadingSpinner'
import { dnsLookup } from '../lib/api'
import type { DNSLookupResult } from '../types'

export default function DNSLookup() {
  const [domain, setDomain] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<DNSLookupResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  async function onSubmit(e: FormEvent) {
    e.preventDefault()
    if (!domain.trim()) return
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      setResult(await dnsLookup(domain.trim()))
    } catch (e) {
      setError(e instanceof Error ? e.message : 'DNS lookup failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <PageWrapper>
      <div className="max-w-4xl mx-auto px-4 sm:px-6 pt-28 pb-20">
        <div className="mb-8">
          <div className="flex items-center gap-2.5 mb-2">
            <div className="p-2 rounded-lg bg-[#0d6efd]/10 border border-[#0d6efd]/20">
              <Globe2 size={18} className="text-[#0d6efd]" />
            </div>
            <h1 className="text-2xl font-bold text-white">DNS Lookup</h1>
          </div>
          <p className="text-gray-500 text-sm ml-10">Resolve A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, DMARC and SPF records.</p>
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
              Lookup
            </button>
          </div>
          <p className="text-xs text-gray-600 mt-2.5">
            <Info size={11} className="inline mr-1" />
            Enter root domain only.
          </p>
        </form>

        {loading && <div className="glass-card rounded-2xl"><LoadingSpinner label="Resolving DNS records..." /></div>}
        {error && <div className="glass-card rounded-2xl p-5 border border-red-500/25 bg-red-500/5 text-red-400 text-sm font-mono">{error}</div>}

        {result && (
          <div className="glass-card rounded-2xl p-5 space-y-4">
            {(['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'CAA', 'DMARC', 'SPF'] as const).map((type) => (
              <div key={type}>
                <div className="text-xs text-gray-500 font-mono mb-1.5">{type} Record</div>
                <div className="space-y-1.5">
                  {(result.records[type] || []).length > 0 ? (
                    result.records[type].map((row, i) => (
                      <div key={`${type}-${i}`} className="text-sm text-gray-200 font-mono bg-white/3 rounded-lg px-3 py-2">
                        {row}
                      </div>
                    ))
                  ) : (
                    <div className="text-sm text-gray-500 font-mono bg-white/3 rounded-lg px-3 py-2">No record found</div>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </PageWrapper>
  )
}
