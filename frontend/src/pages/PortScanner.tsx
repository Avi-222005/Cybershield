import { useState, FormEvent } from 'react'
import { Search, ScanLine } from 'lucide-react'
import PageWrapper from '../components/ui/PageWrapper'
import LoadingSpinner from '../components/ui/LoadingSpinner'
import { portScan, serviceDetect } from '../lib/api'
import type { PortScanResult } from '../types'

export default function PortScanner() {
  const [target, setTarget] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<PortScanResult | null>(null)
  const [serviceMap, setServiceMap] = useState<Record<number, { service: string; banner?: string | null }>>({})
  const [error, setError] = useState<string | null>(null)

  async function onSubmit(e: FormEvent) {
    e.preventDefault()
    if (!target.trim()) return
    setLoading(true)
    setError(null)
    setResult(null)
    setServiceMap({})
    try {
      const [scanResult, serviceResult] = await Promise.all([
        portScan(target.trim()),
        serviceDetect(target.trim()),
      ])
      setResult(scanResult)
      setServiceMap(
        Object.fromEntries(
          serviceResult.services.map((s) => [
            s.port,
            { service: s.service, banner: s.banner ?? null },
          ]),
        ),
      )
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Port scan failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <PageWrapper>
      <div className="max-w-4xl mx-auto px-4 sm:px-6 pt-28 pb-20">
        <div className="mb-8 flex items-center gap-2.5">
          <div className="p-2 rounded-lg bg-[#0d6efd]/10 border border-[#0d6efd]/20">
            <ScanLine size={18} className="text-[#0d6efd]" />
          </div>
          <h1 className="text-2xl font-bold text-white">Port &amp; Service Scanner</h1>
        </div>

        <form onSubmit={onSubmit} className="glass-card rounded-2xl p-5 mb-6">
          <div className="flex gap-3">
            <input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="8.8.8.8 or example.com"
              className="cyber-input flex-1 px-4 py-3 rounded-xl text-sm font-mono"
            />
            <button className="flex items-center gap-2 px-6 py-3 bg-[#0d6efd] hover:bg-[#0b5ed7] !text-white font-semibold rounded-xl text-sm">
              <Search size={16} />
              Scan
            </button>
          </div>
        </form>

        {loading && <div className="glass-card rounded-2xl"><LoadingSpinner label="Scanning ports and detecting services..." /></div>}
        {error && <div className="glass-card rounded-2xl p-5 border border-red-500/25 bg-red-500/5 text-red-400 text-sm font-mono">{error}</div>}

        {result && (
          <div className="glass-card rounded-2xl p-5">
            <div className="text-xs text-gray-500 font-mono mb-3">Resolved IP: {result.resolved_ip}</div>
            <div className="overflow-x-auto rounded-xl border border-white/10">
              <table className="w-full min-w-[680px] text-left table-auto">
                <thead className="bg-white/5">
                  <tr>
                    <th className="px-3 py-2.5 text-xs text-gray-500 font-mono">Port</th>
                    <th className="px-3 py-2.5 text-xs text-gray-500 font-mono">Status</th>
                    <th className="px-3 py-2.5 text-xs text-gray-500 font-mono">Service</th>
                    <th className="px-3 py-2.5 text-xs text-gray-500 font-mono">Banner</th>
                  </tr>
                </thead>
                <tbody>
                  {result.ports.map((p) => (
                    <tr key={p.port} className="border-t border-white/10">
                      <td className="px-3 py-2.5 text-sm text-gray-200 font-mono">:{p.port}</td>
                      <td className="px-3 py-2.5">
                        <span
                          className={`text-xs font-mono px-2 py-1 rounded border ${
                            p.status === 'open'
                              ? 'text-green-400 border-green-500/30 bg-green-500/10'
                              : 'text-gray-500 border-white/10 bg-white/3'
                          }`}
                        >
                          {p.status.toUpperCase()}
                        </span>
                      </td>
                      <td className="px-3 py-2.5 text-sm text-blue-300 font-mono">
                        {p.status === 'open' ? serviceMap[p.port]?.service || 'Unknown' : '-'}
                      </td>
                      <td className="px-3 py-2.5 text-xs text-gray-500 font-mono whitespace-normal break-all align-top">
                        {p.status === 'open' ? (
                          <span className="block">{serviceMap[p.port]?.banner || '-'}</span>
                        ) : (
                          '-'
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </PageWrapper>
  )
}
