import { useState } from 'react'
import { ChevronDown, ChevronUp, AlertTriangle, AlertCircle, CheckCircle } from 'lucide-react'
import { cn } from '../../lib/utils'
import type { VendorEntry } from '../../types'

interface VendorTableProps {
  malicious: VendorEntry[]
  suspicious: VendorEntry[]
  clean: string[]
  stats?: {
    malicious: number
    suspicious: number
    harmless?: number
    undetected?: number
  }
}

type Tab = 'all' | 'malicious' | 'suspicious' | 'clean'

export default function VendorTable({ malicious, suspicious, clean, stats }: VendorTableProps) {
  const [tab, setTab] = useState<Tab>('all')
  const [showClean, setShowClean] = useState(false)

  const tabs: { key: Tab; label: string; count: number; color: string }[] = [
    { key: 'all', label: 'All', count: malicious.length + suspicious.length + clean.length, color: 'text-gray-400' },
    { key: 'malicious', label: 'Malicious', count: malicious.length, color: 'text-red-400' },
    { key: 'suspicious', label: 'Suspicious', count: suspicious.length, color: 'text-yellow-400' },
    { key: 'clean', label: 'Clean', count: clean.length, color: 'text-green-400' },
  ]

  return (
    <div className="glass-card rounded-xl overflow-hidden">
      {/* Stats summary */}
      {stats && (
        <div className="grid grid-cols-3 divide-x divide-cyber-border border-b border-cyber-border">
          <div className="px-4 py-3 text-center">
            <div className="text-xl font-bold font-mono text-red-400">{stats.malicious}</div>
            <div className="text-xs text-gray-500 mt-0.5">Malicious</div>
          </div>
          <div className="px-4 py-3 text-center">
            <div className="text-xl font-bold font-mono text-yellow-400">{stats.suspicious}</div>
            <div className="text-xs text-gray-500 mt-0.5">Suspicious</div>
          </div>
          <div className="px-4 py-3 text-center">
            <div className="text-xl font-bold font-mono text-green-400">
              {(stats.harmless ?? 0) + (stats.undetected ?? 0) + clean.length}
            </div>
            <div className="text-xs text-gray-500 mt-0.5">Clean</div>
          </div>
        </div>
      )}

      {/* Tabs */}
      <div className="flex border-b border-cyber-border px-4 pt-2 gap-1">
        {tabs.map((t) => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            className={cn(
              'px-3 py-2 text-xs font-mono rounded-t-md transition-all flex items-center gap-1.5 border-b-2',
              tab === t.key
                ? `${t.color} border-current bg-white/5`
                : 'text-gray-500 border-transparent hover:text-gray-300',
            )}
          >
            {t.label}
            <span className="text-[10px] px-1 py-0.5 rounded bg-white/5">{t.count}</span>
          </button>
        ))}
      </div>

      {/* Content */}
      <div className="p-4 space-y-1.5 max-h-72 overflow-y-auto">
        {/* Malicious vendors */}
        {(tab === 'all' || tab === 'malicious') && malicious.map((v) => (
          <div
            key={v.name}
            className="flex items-center justify-between px-3 py-2 rounded-lg bg-red-500/5 border border-red-500/15"
          >
            <div className="flex items-center gap-2">
              <AlertTriangle size={13} className="text-red-400 shrink-0" />
              <span className="text-sm font-medium text-gray-200">{v.name}</span>
            </div>
            <span className="text-xs text-red-400 font-mono bg-red-500/10 px-2 py-0.5 rounded">
              {v.result}
            </span>
          </div>
        ))}

        {/* Suspicious vendors */}
        {(tab === 'all' || tab === 'suspicious') && suspicious.map((v) => (
          <div
            key={v.name}
            className="flex items-center justify-between px-3 py-2 rounded-lg bg-yellow-500/5 border border-yellow-500/15"
          >
            <div className="flex items-center gap-2">
              <AlertCircle size={13} className="text-yellow-400 shrink-0" />
              <span className="text-sm font-medium text-gray-200">{v.name}</span>
            </div>
            <span className="text-xs text-yellow-400 font-mono bg-yellow-500/10 px-2 py-0.5 rounded">
              {v.result}
            </span>
          </div>
        ))}

        {/* Clean vendors */}
        {(tab === 'all' || tab === 'clean') && (
          <>
            {clean.slice(0, showClean ? clean.length : 6).map((v) => (
              <div
                key={v}
                className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-green-500/5 border border-green-500/10"
              >
                <CheckCircle size={13} className="text-green-400 shrink-0" />
                <span className="text-sm text-gray-400">{v}</span>
              </div>
            ))}
            {clean.length > 6 && (
              <button
                onClick={() => setShowClean((v) => !v)}
                className="w-full flex items-center justify-center gap-1.5 py-1.5 text-xs text-gray-500 hover:text-cyan-400 transition-colors"
              >
                {showClean ? (
                  <><ChevronUp size={13} /> Show less</>
                ) : (
                  <><ChevronDown size={13} /> Show {clean.length - 6} more clean vendors</>
                )}
              </button>
            )}
          </>
        )}

        {/* Empty state */}
        {tab === 'malicious' && malicious.length === 0 && (
          <p className="text-center text-sm text-gray-500 py-4">No malicious detections</p>
        )}
        {tab === 'suspicious' && suspicious.length === 0 && (
          <p className="text-center text-sm text-gray-500 py-4">No suspicious detections</p>
        )}
      </div>
    </div>
  )
}
