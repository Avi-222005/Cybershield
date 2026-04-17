import { useMemo, useState } from 'react'
import { AlertTriangle, FileJson2, ShieldAlert } from 'lucide-react'
import PageWrapper from '../../components/ui/PageWrapper'
import {
  CopyButton,
  EmptyState,
  ErrorAlert,
  ResultCard,
  ToolHeader,
} from '../../components/ui/tools'
import { decodeJwtToken } from '../../lib/tools'

export default function JwtDecoderTool() {
  const [tokenInput, setTokenInput] = useState('')

  const parsed = useMemo(() => {
    if (!tokenInput.trim()) {
      return { data: null as ReturnType<typeof decodeJwtToken> | null, error: null as string | null }
    }
    try {
      return { data: decodeJwtToken(tokenInput), error: null }
    } catch (err) {
      return {
        data: null,
        error: err instanceof Error ? err.message : 'Unable to decode JWT',
      }
    }
  }, [tokenInput])

  return (
    <PageWrapper>
      <div className="max-w-6xl mx-auto px-4 sm:px-6 pt-28 pb-20 space-y-5">
        <ToolHeader
          icon={FileJson2}
          title="JWT Decoder"
          description="Decode JWT header and payload locally in your browser. No token data is sent to backend services."
        />

        <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-amber-200 text-sm font-mono flex items-start gap-2">
          <ShieldAlert size={14} className="mt-0.5 shrink-0" />
          Decoded only. Signature not verified.
        </div>

        <ResultCard title="JWT Input" description="Paste a token in header.payload.signature format.">
          <textarea
            value={tokenInput}
            onChange={(event) => setTokenInput(event.target.value)}
            rows={6}
            placeholder="eyJhbGciOi..."
            className="cyber-input w-full rounded-xl px-4 py-3 text-sm font-mono"
          />
        </ResultCard>

        {parsed.error && <ErrorAlert message={parsed.error} />}

        {parsed.data ? (
          <>
            <div className="grid lg:grid-cols-2 gap-4">
              <ResultCard
                title="Header"
                description="Decoded JWT header"
                actions={<CopyButton value={JSON.stringify(parsed.data.header, null, 2)} label="Copy JSON" />}
              >
                <pre className="rounded-lg border border-white/10 bg-[#08101d] p-3 text-xs text-gray-200 font-mono overflow-auto max-h-[360px]">
                  {JSON.stringify(parsed.data.header, null, 2)}
                </pre>
              </ResultCard>

              <ResultCard
                title="Payload"
                description="Decoded JWT payload"
                actions={<CopyButton value={JSON.stringify(parsed.data.payload, null, 2)} label="Copy JSON" />}
              >
                <pre className="rounded-lg border border-white/10 bg-[#08101d] p-3 text-xs text-gray-200 font-mono overflow-auto max-h-[360px]">
                  {JSON.stringify(parsed.data.payload, null, 2)}
                </pre>
              </ResultCard>
            </div>

            <ResultCard title="Claims Summary" description="Common claim fields and time interpretation.">
              <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-2 mb-3">
                {[
                  { label: 'sub', value: String(parsed.data.payload.sub ?? 'N/A') },
                  { label: 'iss', value: String(parsed.data.payload.iss ?? 'N/A') },
                  { label: 'aud', value: Array.isArray(parsed.data.payload.aud) ? parsed.data.payload.aud.join(', ') : String(parsed.data.payload.aud ?? 'N/A') },
                  { label: 'iat', value: parsed.data.issuedAtReadable || 'N/A' },
                  { label: 'exp', value: parsed.data.expiresAtReadable || 'N/A' },
                  { label: 'Expired?', value: parsed.data.isExpired === null ? 'Unknown' : parsed.data.isExpired ? 'Yes' : 'No' },
                ].map((entry) => (
                  <div key={entry.label} className="rounded-lg border border-white/10 bg-white/3 p-2.5">
                    <div className="text-[11px] text-gray-500 font-mono">{entry.label}</div>
                    <div className="text-sm text-gray-200 font-mono break-words">{entry.value}</div>
                  </div>
                ))}
              </div>

              {parsed.data.warnings.length > 0 && (
                <div className="rounded-lg border border-orange-500/30 bg-orange-500/10 px-3 py-2">
                  <div className="text-xs text-orange-200 font-mono mb-1.5 flex items-center gap-1.5">
                    <AlertTriangle size={13} />
                    Warnings
                  </div>
                  <ul className="space-y-1">
                    {parsed.data.warnings.map((warning) => (
                      <li key={warning} className="text-xs text-orange-100 font-mono">{warning}</li>
                    ))}
                  </ul>
                </div>
              )}
            </ResultCard>
          </>
        ) : (
          <ResultCard title="Decoded Output" description="Header and payload will appear once a valid token is pasted.">
            <EmptyState title="No Token Decoded" description="Paste a JWT to inspect its claims locally." />
          </ResultCard>
        )}
      </div>
    </PageWrapper>
  )
}
