import { useState, FormEvent } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  FileSearch,
  Search,
  Info,
  Calendar,
  Building2,
  Globe,
  Server,
  Mail,
  Phone,
  MapPin,
  User,
} from 'lucide-react'
import dayjs from 'dayjs'
import PageWrapper from '../components/ui/PageWrapper'
import LoadingSpinner from '../components/ui/LoadingSpinner'
import { whoisLookup } from '../lib/api'
import type { WhoisResult } from '../types'

function InfoRow({ label, value }: { label: string; value?: string }) {
  if (!value || value === 'N/A' || value === '') return null
  return (
    <div className="flex items-start gap-2 py-2 border-b border-white/5 last:border-0">
      <span className="text-xs text-gray-500 font-mono w-36 shrink-0 pt-0.5">{label}</span>
      <span className="text-sm text-gray-200 break-all">{value}</span>
    </div>
  )
}

function Section({
  title,
  icon: Icon,
  children,
  color = 'text-[#0d6efd]',
}: {
  title: string
  icon: React.ElementType
  children: React.ReactNode
  color?: string
}) {
  return (
    <div className="glass-card rounded-2xl p-5">
      <h3 className={`text-sm font-semibold text-white mb-3 flex items-center gap-2`}>
        <Icon size={15} className={color} />
        {title}
      </h3>
      <div>{children}</div>
    </div>
  )
}

function ContactCard({ data }: { data: Record<string, string> }) {
  const fields = [
    { key: 'name', label: 'Name', icon: User },
    { key: 'organization', label: 'Organization', icon: Building2 },
    { key: 'email', label: 'Email', icon: Mail },
    { key: 'phone', label: 'Phone', icon: Phone },
    { key: 'country', label: 'Country', icon: Globe },
    { key: 'city', label: 'City', icon: MapPin },
    { key: 'state', label: 'State', icon: MapPin },
    { key: 'postalCode', label: 'Postal Code', icon: MapPin },
  ]
  const hasData = fields.some(({ key }) => data?.[key] && data[key] !== 'N/A')
  if (!hasData) return <p className="text-xs text-gray-500 italic">No contact information available.</p>

  return (
    <div className="space-y-0">
      {fields.map(({ key, label }) => (
        <InfoRow key={key} label={label} value={data?.[key]} />
      ))}
    </div>
  )
}

function formatDate(val?: string) {
  if (!val || val === 'N/A') return val
  const d = dayjs(val)
  return d.isValid() ? d.format('MMM D, YYYY') : val
}

export default function WhoisLookup() {
  const [domain, setDomain] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<WhoisResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    const trimmed = domain.trim().replace(/^https?:\/\//, '')
    if (!trimmed) return

    setLoading(true)
    setResult(null)
    setError(null)

    try {
      const data = await whoisLookup(trimmed)
      setResult(data)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Lookup failed. Please try again.')
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
              <FileSearch size={18} className="text-[#0d6efd]" />
            </div>
            <h1 className="text-2xl font-bold text-white">WHOIS Lookup</h1>
          </div>
          <p className="text-gray-500 text-sm ml-10">
            Domain registration data — registrar, ownership, dates, name servers & contact details
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
              placeholder="example.com"
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
              Lookup
            </button>
          </div>
          <p className="text-xs text-gray-600 mt-2.5">
            <Info size={11} className="inline mr-1" />
            Requires a valid domain name (e.g., google.com). Subdomains and IP addresses not supported.
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
              <LoadingSpinner label="Querying WHOIS database…" />
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
              {/* ── Domain summary ── */}
              <div className="glass-card rounded-2xl p-5">
                <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
                  <div>
                    <h2 className="text-xl font-bold font-mono text-[#0d6efd]">
                      {result.domainName}
                      <span className="text-gray-500">{result.domainNameExt}</span>
                    </h2>
                    <p className="text-xs text-gray-500 mt-0.5 font-mono">{result.whoisServer}</p>
                  </div>
                  <span
                    className={`text-xs px-3 py-1.5 rounded-full border font-mono ${
                      result.status?.toLowerCase().includes('active')
                        ? 'text-green-400 bg-green-500/10 border-green-500/25'
                        : 'text-gray-400 bg-white/5 border-white/10'
                    }`}
                  >
                    {result.status}
                  </span>
                </div>

                {result.lookupSources && result.lookupSources.length > 0 && (
                  <div className="mb-4 flex flex-wrap gap-2 items-center">
                    <span className="text-[11px] text-gray-500 font-mono">Sources:</span>
                    {result.lookupSources.map((source) => (
                      <span
                        key={source}
                        className="text-[11px] font-mono text-[#6ea8fe] bg-[#0d6efd]/10 border border-[#0d6efd]/25 px-2 py-0.5 rounded"
                      >
                        {source}
                      </span>
                    ))}
                  </div>
                )}

                <div className="grid sm:grid-cols-3 gap-3">
                  <div className="bg-white/3 rounded-lg px-3 py-2.5">
                    <div className="text-xs text-gray-500 font-mono">Domain Age</div>
                    <div className="text-sm font-semibold text-white mt-0.5">{result.estimatedDomainAge} days</div>
                  </div>
                  <div className="bg-white/3 rounded-lg px-3 py-2.5">
                    <div className="text-xs text-gray-500 font-mono">Contact Email</div>
                    <div className="text-sm text-gray-200 mt-0.5 truncate">{result.contactEmail || 'N/A'}</div>
                  </div>
                  <div className="bg-white/3 rounded-lg px-3 py-2.5">
                    <div className="text-xs text-gray-500 font-mono">Registrar IANA ID</div>
                    <div className="text-sm font-mono text-[#0d6efd] mt-0.5">{result.registrarIANAID || 'N/A'}</div>
                  </div>
                </div>

                {result.lookupNotes && result.lookupNotes.length > 0 && (
                  <div className="mt-4 rounded-xl border border-amber-500/25 bg-amber-500/8 p-3">
                    <div className="text-[11px] text-amber-300 font-mono mb-1">Lookup Notes</div>
                    <ul className="space-y-1">
                      {result.lookupNotes.map((note) => (
                        <li key={note} className="text-xs text-amber-200/90 font-mono">- {note}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>

              {/* ── Important dates ── */}
              <Section title="Important Dates" icon={Calendar} color="text-[#0d6efd]">
                <div className="grid sm:grid-cols-3 gap-3">
                  {[
                    { label: 'Created', value: result.createdDate },
                    { label: 'Updated', value: result.updatedDate },
                    { label: 'Expires', value: result.expiresDate },
                  ].map(({ label, value }) => (
                    <div key={label} className="bg-white/3 rounded-lg px-3 py-2.5">
                      <div className="text-xs text-gray-500 font-mono">{label}</div>
                      <div className="text-sm font-mono text-gray-200 mt-0.5">
                        {formatDate(value) || 'N/A'}
                      </div>
                    </div>
                  ))}
                </div>
              </Section>

              {/* ── Registrar ── */}
              <Section title="Registrar Information" icon={Building2} color="text-[#0d6efd]">
                <InfoRow label="Registrar" value={result.registrarName} />
                <InfoRow label="IANA ID" value={result.registrarIANAID} />
                <InfoRow label="WHOIS Server" value={result.whoisServer} />
                <InfoRow label="Registrar URL" value={result.registrarURL} />
                <InfoRow label="DNSSEC" value={result.dnssec} />
                <InfoRow label="Privacy" value={result.privacyProtection} />
              </Section>

              {!!result.ips?.length && (
                <Section title="Domain Infrastructure" icon={Globe} color="text-cyan-400">
                  <div className="text-xs text-gray-500 font-mono mb-2">Resolved IP Addresses</div>
                  <div className="flex flex-wrap gap-2">
                    {result.ips.map((ip) => (
                      <span
                        key={ip}
                        className="text-xs font-mono text-cyan-300 bg-cyan-500/8 border border-cyan-500/20 px-2.5 py-1 rounded-lg"
                      >
                        {ip}
                      </span>
                    ))}
                  </div>
                </Section>
              )}

              {/* ── Name servers ── */}
              {result.nameServers?.length > 0 && (
                <Section title="Name Servers" icon={Server} color="text-[#3b82f6]">
                  <div className="space-y-2">
                    {result.nameServers.map((ns) => {
                      const nsIps = result.nameServerIPs?.[ns] || []
                      return (
                        <div key={ns} className="rounded-lg border border-white/10 bg-white/3 p-2.5">
                          <div className="text-xs font-mono text-purple-300 break-all">{ns}</div>
                          <div className="mt-1.5 flex flex-wrap gap-1.5">
                            {nsIps.length > 0 ? (
                              nsIps.map((ip) => (
                                <span
                                  key={`${ns}-${ip}`}
                                  className="text-[11px] font-mono text-blue-200 bg-blue-500/10 border border-blue-500/25 px-2 py-0.5 rounded"
                                >
                                  {ip}
                                </span>
                              ))
                            ) : (
                              <span className="text-[11px] text-gray-500 font-mono">IP not resolved</span>
                            )}
                          </div>
                        </div>
                      )
                    })}
                  </div>
                </Section>
              )}

              {/* ── Registrant ── */}
              <Section title="Registrant Information" icon={User} color="text-emerald-400">
                <ContactCard data={result.registrant} />
              </Section>

              {/* ── Admin contact ── */}
              <Section title="Administrative Contact" icon={User} color="text-[#0d6efd]">
                <ContactCard data={result.administrativeContact} />
              </Section>

              {/* ── Technical contact ── */}
              <Section title="Technical Contact" icon={User} color="text-gray-400">
                <ContactCard data={result.technicalContact} />
              </Section>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </PageWrapper>
  )
}
