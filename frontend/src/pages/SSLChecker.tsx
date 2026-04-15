import { useState, FormEvent } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Lock, Search, Info, ShieldCheck, ShieldX, Calendar, Building2, Globe } from 'lucide-react'
import dayjs from 'dayjs'
import PageWrapper from '../components/ui/PageWrapper'
import LoadingSpinner from '../components/ui/LoadingSpinner'
import { checkSsl } from '../lib/api'
import type { SSLResult } from '../types'

function ExpiryBar({ days }: { days: number }) {
  const clamped = Math.min(Math.max(days, 0), 365)
  const pct = (clamped / 365) * 100
  const color = days < 0 ? '#ef4444' : days < 30 ? '#f97316' : days < 90 ? '#f59e0b' : '#22c55e'

  return (
    <div>
      <div className="flex justify-between text-xs text-gray-500 font-mono mb-1.5">
        <span>Expiry</span>
        <span style={{ color }}>
          {days < 0 ? 'EXPIRED' : `${days} days remaining`}
        </span>
      </div>
      <div className="w-full h-2 bg-cyber-border rounded-full overflow-hidden">
        <motion.div
          className="h-full rounded-full"
          style={{ background: color }}
          initial={{ width: 0 }}
          animate={{ width: `${pct}%` }}
          transition={{ duration: 0.8, ease: 'easeOut' }}
        />
      </div>
    </div>
  )
}

export default function SSLChecker() {
  const [domain, setDomain] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<SSLResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    const trimmed = domain.trim().replace(/^https?:\/\//, '')
    if (!trimmed) return

    setLoading(true)
    setResult(null)
    setError(null)

    try {
      const data = await checkSsl(trimmed)
      setResult(data)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Check failed. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <PageWrapper>
      <div className="max-w-3xl mx-auto px-4 sm:px-6 pt-28 pb-20">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-2.5 mb-2">
            <div className="p-2 rounded-lg bg-[#0d6efd]/10 border border-[#0d6efd]/20">
              <Lock size={18} className="text-[#0d6efd]" />
            </div>
            <h1 className="text-2xl font-bold text-white">SSL Certificate Checker</h1>
          </div>
          <p className="text-gray-500 text-sm ml-10">
            Validate TLS certificates, verify CA trust chains, and track expiry dates
          </p>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="glass-card rounded-2xl p-5 mb-6">
          <label className="block text-xs font-mono text-gray-400 mb-2 uppercase tracking-wider">
            Domain Name
          </label>
          <div className="flex gap-3">
            <input
              type="text"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="example.com or https://example.com"
              className="cyber-input flex-1 px-4 py-3 rounded-xl text-sm font-mono"
              required
              disabled={loading}
            />
            <button
              type="submit"
              disabled={loading || !domain.trim()}
              className="flex items-center gap-2 px-6 py-3 bg-[#0d6efd] hover:bg-[#0b5ed7] disabled:opacity-50 disabled:cursor-not-allowed !text-white font-semibold rounded-xl transition-colors text-sm shrink-0"
            >
              <Search size={16} />
              Check
            </button>
          </div>
          <p className="text-xs text-gray-600 mt-2.5">
            <Info size={11} className="inline mr-1" />
            Protocol prefix (https://) will be stripped automatically.
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
              <LoadingSpinner label="Connecting to server & reading certificate…" />
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
              {/* Status banner */}
              <div
                className={`glass-card rounded-2xl p-5 border ${
                  result.is_valid
                    ? 'border-emerald-500/25 bg-emerald-500/5'
                    : 'border-red-500/25 bg-red-500/5'
                }`}
              >
                <div className="flex items-center gap-3">
                  {result.is_valid ? (
                    <ShieldCheck size={28} className="text-emerald-400 shrink-0" />
                  ) : (
                    <ShieldX size={28} className="text-red-400 shrink-0" />
                  )}
                  <div>
                    <div
                      className={`text-lg font-bold font-mono ${
                        result.is_valid ? 'text-emerald-400' : 'text-red-400'
                      }`}
                    >
                      {result.is_valid ? 'Certificate Valid' : 'Certificate Invalid'}
                    </div>
                    {result.message && (
                      <p className="text-sm text-gray-400 mt-0.5">{result.message}</p>
                    )}
                  </div>
                </div>
              </div>

              {/* Certificate details */}
              {result.is_valid && (
                <div className="glass-card rounded-2xl p-5 space-y-4">
                  <h3 className="text-sm font-semibold text-white">Certificate Details</h3>

                  <div className="grid sm:grid-cols-2 gap-3">
                    {[
                      { label: 'Issued To (CN)', value: result.subject, icon: Globe },
                      { label: 'Certificate Authority', value: result.issuer, icon: Building2 },
                    ].map(({ label, value, icon: Icon }) => (
                      <div key={label} className="bg-white/3 rounded-lg px-3 py-2.5 flex items-start gap-2">
                        <Icon size={14} className="text-emerald-400 mt-0.5 shrink-0" />
                        <div>
                          <div className="text-xs text-gray-500 font-mono">{label}</div>
                          <div className="text-sm text-gray-200 break-all">{value}</div>
                        </div>
                      </div>
                    ))}
                  </div>

                  {/* Dates */}
                  <div className="grid sm:grid-cols-2 gap-3">
                    {[
                      { label: 'Valid From', value: result.valid_from, icon: Calendar },
                      { label: 'Valid Until', value: result.valid_until, icon: Calendar },
                    ].map(({ label, value, icon: Icon }) => (
                      <div key={label} className="bg-white/3 rounded-lg px-3 py-2.5 flex items-start gap-2">
                        <Icon size={14} className="text-gray-500 mt-0.5 shrink-0" />
                        <div>
                          <div className="text-xs text-gray-500 font-mono">{label}</div>
                          <div className="text-sm text-gray-200 font-mono">
                            {dayjs(value).format('MMM D, YYYY')}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>

                  {/* Expiry bar */}
                  <div className="bg-white/3 rounded-lg px-3 py-3">
                    <ExpiryBar days={result.days_until_expiry} />
                    {result.days_until_expiry < 30 && result.days_until_expiry >= 0 && (
                      <p className="text-xs text-orange-400 mt-2 font-mono">
                        ⚠ Certificate expires soon — renew immediately to avoid service disruption.
                      </p>
                    )}
                    {result.days_until_expiry < 0 && (
                      <p className="text-xs text-red-400 mt-2 font-mono">
                        ✕ Certificate has expired. HTTPS connections will be rejected.
                      </p>
                    )}
                  </div>
                </div>
              )}
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </PageWrapper>
  )
}
