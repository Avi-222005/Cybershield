import { useMemo, useState } from 'react'
import { ArrowRightLeft, Binary, Wand2 } from 'lucide-react'
import PageWrapper from '../../components/ui/PageWrapper'
import {
  CopyButton,
  EmptyState,
  ErrorAlert,
  ResultCard,
  ToolHeader,
} from '../../components/ui/tools'
import {
  decodeUtf8Base64,
  encodeUtf8Base64,
  isLikelyBase64,
} from '../../lib/tools'

type Base64Mode = 'encode' | 'decode' | 'auto'

function transform(mode: Base64Mode, input: string): { output: string; error: string | null; applied: 'encode' | 'decode' } {
  if (!input.trim()) return { output: '', error: null, applied: mode === 'decode' ? 'decode' : 'encode' }

  try {
    if (mode === 'encode') {
      return { output: encodeUtf8Base64(input), error: null, applied: 'encode' }
    }

    if (mode === 'decode') {
      return { output: decodeUtf8Base64(input), error: null, applied: 'decode' }
    }

    if (isLikelyBase64(input)) {
      return { output: decodeUtf8Base64(input), error: null, applied: 'decode' }
    }

    return { output: encodeUtf8Base64(input), error: null, applied: 'encode' }
  } catch {
    return { output: '', error: 'Unable to decode input as Base64 UTF-8 text.', applied: 'decode' }
  }
}

export default function Base64Tool() {
  const [input, setInput] = useState('')
  const [mode, setMode] = useState<Base64Mode>('auto')

  const result = useMemo(() => transform(mode, input), [mode, input])

  function onSwap() {
    setInput(result.output)
    setMode((current) => {
      if (current === 'encode') return 'decode'
      if (current === 'decode') return 'encode'
      return 'auto'
    })
  }

  function onClear() {
    setInput('')
  }

  return (
    <PageWrapper>
      <div className="max-w-6xl mx-auto px-4 sm:px-6 pt-28 pb-20 space-y-5">
        <ToolHeader
          icon={Binary}
          title="Base64 Encoder / Decoder"
          description="Convert UTF-8 text to and from Base64 locally with encode, decode, or auto-detect mode."
        />

        <ResultCard
          title="Conversion Mode"
          description="Auto mode attempts decode for Base64-like input and encode otherwise."
          actions={<span className="text-xs text-gray-500 font-mono">Applied: {result.applied.toUpperCase()}</span>}
        >
          <div className="flex flex-wrap gap-2">
            {[
              { value: 'encode', label: 'Encode' },
              { value: 'decode', label: 'Decode' },
              { value: 'auto', label: 'Auto detect' },
            ].map((entry) => (
              <button
                key={entry.value}
                type="button"
                onClick={() => setMode(entry.value as Base64Mode)}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono border ${
                  mode === entry.value
                    ? 'text-[#6ea8fe] border-[#0d6efd]/35 bg-[#0d6efd]/10'
                    : 'text-gray-300 border-white/15 hover:bg-white/5'
                }`}
              >
                {entry.label}
              </button>
            ))}
          </div>
        </ResultCard>

        <div className="grid xl:grid-cols-[1fr_auto_1fr] gap-3 items-stretch">
          <ResultCard title="Input" description="Paste UTF-8 text or Base64 content.">
            <textarea
              value={input}
              onChange={(event) => setInput(event.target.value)}
              rows={12}
              placeholder="Enter source text"
              className="cyber-input w-full rounded-xl px-4 py-3 text-sm font-mono"
            />
          </ResultCard>

          <div className="flex xl:flex-col items-center justify-center gap-2">
            <button
              type="button"
              onClick={onSwap}
              className="px-3 py-2 rounded-lg border border-white/15 text-gray-200 hover:bg-white/5 inline-flex items-center gap-1.5 text-xs font-mono"
            >
              <ArrowRightLeft size={13} />
              Swap
            </button>
            <button
              type="button"
              onClick={onClear}
              className="px-3 py-2 rounded-lg border border-white/15 text-gray-200 hover:bg-white/5 inline-flex items-center gap-1.5 text-xs font-mono"
            >
              <Wand2 size={13} />
              Clear
            </button>
          </div>

          <ResultCard title="Output" description="Result updates instantly.">
            {result.error ? (
              <ErrorAlert message={result.error} />
            ) : result.output ? (
              <div className="space-y-2">
                <textarea
                  value={result.output}
                  readOnly
                  rows={12}
                  className="cyber-input w-full rounded-xl px-4 py-3 text-sm font-mono"
                />
                <CopyButton value={result.output} label="Copy" />
              </div>
            ) : (
              <EmptyState title="No Output" description="Provide input text to encode or decode." />
            )}
          </ResultCard>
        </div>
      </div>
    </PageWrapper>
  )
}
