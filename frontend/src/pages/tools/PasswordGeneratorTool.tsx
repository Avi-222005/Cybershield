import { useMemo, useState } from 'react'
import { KeyRound, Shuffle } from 'lucide-react'
import PageWrapper from '../../components/ui/PageWrapper'
import {
  CopyButton,
  EmptyState,
  ErrorAlert,
  ResultCard,
  StrengthBadge,
  ToolHeader,
} from '../../components/ui/tools'
import {
  estimatePasswordStrength,
  generatePassword,
} from '../../lib/tools'
import { useToast } from '../../context/ToastContext'

export default function PasswordGeneratorTool() {
  const [length, setLength] = useState(20)
  const [includeUppercase, setIncludeUppercase] = useState(true)
  const [includeLowercase, setIncludeLowercase] = useState(true)
  const [includeNumbers, setIncludeNumbers] = useState(true)
  const [includeSymbols, setIncludeSymbols] = useState(true)
  const [excludeSimilar, setExcludeSimilar] = useState(false)
  const [avoidAmbiguousSymbols, setAvoidAmbiguousSymbols] = useState(true)

  const [password, setPassword] = useState('')
  const [batchPasswords, setBatchPasswords] = useState<string[]>([])
  const [error, setError] = useState<string | null>(null)

  const { pushToast } = useToast()

  const strength = useMemo(() => estimatePasswordStrength(password), [password])

  function getConfig() {
    return {
      length,
      includeUppercase,
      includeLowercase,
      includeNumbers,
      includeSymbols,
      excludeSimilar,
      avoidAmbiguousSymbols,
    }
  }

  function onGenerateSingle() {
    setError(null)
    try {
      const next = generatePassword(getConfig())
      setPassword(next)
      setBatchPasswords([])
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to generate password')
    }
  }

  function onGenerateBatch() {
    setError(null)
    try {
      const list = Array.from({ length: 5 }, () => generatePassword(getConfig()))
      setBatchPasswords(list)
      setPassword(list[0])
      pushToast('Generated 5 password options', 'success')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to generate passwords')
    }
  }

  return (
    <PageWrapper>
      <div className="max-w-5xl mx-auto px-4 sm:px-6 pt-28 pb-20 space-y-5">
        <ToolHeader
          icon={KeyRound}
          title="Password Generator"
          description="Generate high-entropy passwords with fine-grained controls. Everything runs locally in your browser."
        />

        <ResultCard title="Generator Controls" description="Tune character classes and produce one or many secure passwords.">
          <div className="space-y-4">
            <div>
              <div className="flex items-center justify-between mb-2">
                <label className="text-xs text-gray-500 font-mono">Length</label>
                <span className="text-xs text-gray-300 font-mono">{length}</span>
              </div>
              <input
                type="range"
                min={8}
                max={64}
                value={length}
                onChange={(event) => setLength(Number(event.target.value))}
                className="w-full accent-[#0d6efd]"
              />
            </div>

            <div className="grid sm:grid-cols-2 gap-2">
              {[
                { label: 'Include uppercase', value: includeUppercase, setValue: setIncludeUppercase },
                { label: 'Include lowercase', value: includeLowercase, setValue: setIncludeLowercase },
                { label: 'Include numbers', value: includeNumbers, setValue: setIncludeNumbers },
                { label: 'Include symbols', value: includeSymbols, setValue: setIncludeSymbols },
                { label: 'Exclude similar chars (O,0,l,1)', value: excludeSimilar, setValue: setExcludeSimilar },
                { label: 'Avoid ambiguous symbols', value: avoidAmbiguousSymbols, setValue: setAvoidAmbiguousSymbols },
              ].map((option) => (
                <label key={option.label} className="rounded-lg border border-white/10 bg-white/3 px-3 py-2 flex items-center gap-2 text-sm text-gray-200">
                  <input
                    type="checkbox"
                    checked={option.value}
                    onChange={(event) => option.setValue(event.target.checked)}
                    className="accent-[#0d6efd]"
                  />
                  <span className="font-mono text-xs">{option.label}</span>
                </label>
              ))}
            </div>

            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                onClick={onGenerateSingle}
                className="px-4 py-2.5 rounded-lg bg-[#0d6efd] hover:bg-[#0b5ed7] text-white text-sm font-semibold"
              >
                Generate
              </button>
              <CopyButton value={password} label="Copy" successMessage="Password copied" />
              <button
                type="button"
                onClick={onGenerateBatch}
                className="inline-flex items-center gap-1.5 px-4 py-2.5 rounded-lg border border-white/15 text-gray-200 text-sm font-semibold hover:bg-white/5"
              >
                <Shuffle size={13} />
                Generate x5 passwords
              </button>
            </div>

            {error && <ErrorAlert message={error} />}
          </div>
        </ResultCard>

        <ResultCard title="Generated Password" description="Use the strength meter and entropy estimate to validate quality.">
          {password ? (
            <div className="space-y-3">
              <div className="rounded-lg border border-white/10 bg-white/3 p-3">
                <div className="text-sm text-gray-100 font-mono break-all">{password}</div>
              </div>

              <div className="flex flex-wrap gap-2 items-center">
                <StrengthBadge level={strength.level} />
                <span className="text-xs text-gray-300 font-mono">Entropy estimate: {strength.entropyBits} bits</span>
              </div>

              <div className="h-2 rounded-full bg-white/10 overflow-hidden">
                <div
                  className={`h-full transition-all duration-300 ${
                    strength.level === 'Weak'
                      ? 'bg-red-500'
                      : strength.level === 'Medium'
                      ? 'bg-amber-500'
                      : strength.level === 'Strong'
                      ? 'bg-cyan-500'
                      : 'bg-green-500'
                  }`}
                  style={{ width: `${strength.scorePercent}%` }}
                />
              </div>

              {batchPasswords.length > 0 && (
                <div className="space-y-2">
                  <div className="text-xs text-gray-500 font-mono">Alternative options</div>
                  {batchPasswords.map((entry) => (
                    <div key={entry} className="rounded-lg border border-white/10 bg-white/3 p-2.5 flex items-center justify-between gap-2">
                      <span className="text-xs text-gray-200 font-mono break-all">{entry}</span>
                      <CopyButton value={entry} label="Copy" />
                    </div>
                  ))}
                </div>
              )}
            </div>
          ) : (
            <EmptyState title="No Password Yet" description="Click Generate to create a secure password." />
          )}
        </ResultCard>
      </div>
    </PageWrapper>
  )
}
