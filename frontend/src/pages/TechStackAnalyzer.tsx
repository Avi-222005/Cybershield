import { useState, FormEvent } from 'react'
import { Search, Brain, Server, Cpu, Palette, Newspaper, Cloud, Shield, CreditCard, Boxes } from 'lucide-react'
import PageWrapper from '../components/ui/PageWrapper'
import LoadingSpinner from '../components/ui/LoadingSpinner'
import { techStackAnalysis } from '../lib/api'
import type { TechStackResult } from '../types'

const categoryIcon: Record<string, React.ElementType> = {
  Server: Server,
  Backend: Cpu,
  Framework: Boxes,
  Frontend: Palette,
  CMS: Newspaper,
  Analytics: Brain,
  'CDN/Security': Cloud,
  Security: Shield,
  Payment: CreditCard,
  Hosting: Cloud,
}

export default function TechStackAnalyzer() {
  const [url, setUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<TechStackResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  async function onSubmit(e: FormEvent) {
    e.preventDefault()
    if (!url.trim()) return
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      setResult(await techStackAnalysis(url.trim()))
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Tech stack analysis failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <PageWrapper>
      <div className="max-w-5xl mx-auto px-4 sm:px-6 pt-28 pb-20">
        <div className="mb-8">
          <div className="flex items-center gap-2.5 mb-2">
            <div className="p-2 rounded-lg bg-[#0d6efd]/10 border border-[#0d6efd]/20">
              <Brain size={18} className="text-[#0d6efd]" />
            </div>
            <h1 className="text-2xl font-bold text-white">Tech Stack Analyzer</h1>
          </div>
          <p className="text-gray-500 text-sm ml-10">Multi-signal detection of 100+ technologies.</p>
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

        {loading && <div className="glass-card rounded-2xl"><LoadingSpinner label="Analyzing technology fingerprints..." /></div>}
        {error && <div className="glass-card rounded-2xl p-5 border border-red-500/25 bg-red-500/5 text-red-400 text-sm font-mono">{error}</div>}

        {result && (
          <div className="space-y-5">
            <div className="glass-card rounded-2xl p-5">
              <h2 className="text-lg font-semibold text-white mb-3">🧠 Tech Stack Analysis</h2>
              <div className="text-xs text-gray-500 font-mono mb-2">Analyzed URL: {result.url}</div>
              <div className="text-sm text-gray-300 font-mono">{result.technologies.join(', ') || 'No technologies detected'}</div>
            </div>

            <div className="grid md:grid-cols-2 gap-4">
              {Object.entries(result.categorized).map(([category, techs]) => {
                const Icon = categoryIcon[category] || Boxes
                return (
                  <div key={category} className="glass-card rounded-2xl p-4">
                    <div className="flex items-center gap-2 mb-3">
                      <Icon size={16} className="text-[#0d6efd]" />
                      <h3 className="text-sm font-semibold text-white">{category}</h3>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {techs.map((tech) => (
                        <span key={tech} className="text-xs px-2.5 py-1 rounded-full border border-[#0d6efd]/20 bg-[#0d6efd]/10 text-[#0d6efd] font-mono">
                          {tech}
                        </span>
                      ))}
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        )}
      </div>
    </PageWrapper>
  )
}
