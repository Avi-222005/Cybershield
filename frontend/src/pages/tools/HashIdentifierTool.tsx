import { useMemo, useState } from 'react'
import { Fingerprint } from 'lucide-react'
import PageWrapper from '../../components/ui/PageWrapper'
import {
  CopyButton,
  EmptyState,
  ResultCard,
  ToolHeader,
} from '../../components/ui/tools'
import { identifyHash } from '../../lib/tools'
import type { HashConfidence } from '../../types/tools'

function confidenceClass(confidence: HashConfidence): string {
  if (confidence === 'High') return 'text-green-300 border-green-500/35 bg-green-500/10'
  if (confidence === 'Medium') return 'text-amber-300 border-amber-500/35 bg-amber-500/10'
  return 'text-gray-300 border-white/20 bg-white/5'
}

export default function HashIdentifierTool() {
  const [input, setInput] = useState('')

  const analysis = useMemo(() => {
    if (!input.trim()) return null
    return identifyHash(input)
  }, [input])

  return (
    <PageWrapper>
      <div className="max-w-5xl mx-auto px-4 sm:px-6 pt-28 pb-20 space-y-5">
        <ToolHeader
          icon={Fingerprint}
          title="Hash Identifier"
          description="Identify likely hash types by length, character set, prefixes, and common signatures."
        />

        <ResultCard title="Hash Input" description="Paste hash string to analyze.">
          <textarea
            value={input}
            onChange={(event) => setInput(event.target.value)}
            rows={5}
            placeholder="e3b0c44298fc1c149afbf4c8996fb924..."
            className="cyber-input w-full rounded-xl px-4 py-3 text-sm font-mono"
          />
        </ResultCard>

        {analysis ? (
          <>
            <ResultCard title="Signature Analysis" description="Basic structure and detected format hints.">
              <div className="grid sm:grid-cols-3 gap-2 mb-3">
                <div className="rounded-lg border border-white/10 bg-white/3 p-2.5">
                  <div className="text-[11px] text-gray-500 font-mono">Length</div>
                  <div className="text-sm text-gray-200 font-mono">{analysis.length}</div>
                </div>
                <div className="rounded-lg border border-white/10 bg-white/3 p-2.5">
                  <div className="text-[11px] text-gray-500 font-mono">Character Set</div>
                  <div className="text-sm text-gray-200 font-mono">{analysis.charset}</div>
                </div>
                <div className="rounded-lg border border-white/10 bg-white/3 p-2.5">
                  <div className="text-[11px] text-gray-500 font-mono">Prefix</div>
                  <div className="text-sm text-gray-200 font-mono">{analysis.prefix || 'N/A'}</div>
                </div>
              </div>
              <div className="rounded-lg border border-white/10 bg-white/3 p-3 text-xs text-gray-300 font-mono break-all">
                <div className="mb-1 text-gray-500">Normalized Input</div>
                {analysis.normalized}
              </div>
            </ResultCard>

            <ResultCard title="Likely Match Types" description="Ordered by confidence and known pattern signatures." actions={<CopyButton value={analysis.matches.map((m) => `${m.type} (${m.confidence})`).join('\n')} label="Copy List" />}>
              <div className="space-y-2">
                {analysis.matches.map((match, index) => (
                  <div key={`${match.type}-${index}`} className="rounded-lg border border-white/10 bg-white/3 px-3 py-2.5">
                    <div className="flex items-center justify-between gap-2 mb-1">
                      <span className="text-sm text-gray-200">{index + 1}. {match.type}</span>
                      <span className={`text-[11px] px-2 py-0.5 rounded border font-mono ${confidenceClass(match.confidence)}`}>
                        {match.confidence}
                      </span>
                    </div>
                    {match.notes && <div className="text-xs text-gray-500 font-mono">{match.notes}</div>}
                  </div>
                ))}
              </div>
            </ResultCard>
          </>
        ) : (
          <ResultCard title="Likely Match Types" description="Results appear after input analysis.">
            <EmptyState title="No Hash Analyzed" description="Paste a hash to identify likely algorithms." />
          </ResultCard>
        )}
      </div>
    </PageWrapper>
  )
}
