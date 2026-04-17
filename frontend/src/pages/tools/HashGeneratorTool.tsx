import { FormEvent, useMemo, useState } from 'react'
import { FileDigit, FileUp, Hash, Scale } from 'lucide-react'
import PageWrapper from '../../components/ui/PageWrapper'
import {
  CopyButton,
  EmptyState,
  ErrorAlert,
  ResultCard,
  ToolHeader,
} from '../../components/ui/tools'
import {
  downloadTextReport,
  formatBytes,
  hashFileInBrowser,
  hashText,
  TEXT_HASH_ALGORITHMS,
} from '../../lib/tools'
import type { FileHashResult, HashAlgorithm, TextHashResult } from '../../types/tools'
import { useToast } from '../../context/ToastContext'

function HashOutput({ result }: { result: TextHashResult }) {
  return (
    <div className="space-y-2">
      <div className="rounded-lg border border-white/10 bg-white/3 p-3">
        <div className="text-xs text-gray-500 font-mono mb-1">Hash Output</div>
        <div className="text-sm text-gray-200 font-mono break-all">{result.hash}</div>
      </div>
      <div className="grid sm:grid-cols-3 gap-2">
        <div className="rounded-lg border border-white/10 bg-white/3 p-2.5 text-xs font-mono text-gray-300">Algorithm: {result.algorithm}</div>
        <div className="rounded-lg border border-white/10 bg-white/3 p-2.5 text-xs font-mono text-gray-300">Characters: {result.length}</div>
        <div className="rounded-lg border border-white/10 bg-white/3 p-2.5 text-xs font-mono text-gray-300">Output: Hexadecimal</div>
      </div>
    </div>
  )
}

export default function HashGeneratorTool() {
  const [textInput, setTextInput] = useState('')
  const [algorithm, setAlgorithm] = useState<HashAlgorithm>('SHA256')
  const [textResult, setTextResult] = useState<TextHashResult | null>(null)
  const [textError, setTextError] = useState<string | null>(null)
  const [hashingText, setHashingText] = useState(false)

  const [fileResult, setFileResult] = useState<FileHashResult | null>(null)
  const [fileHashing, setFileHashing] = useState(false)
  const [fileError, setFileError] = useState<string | null>(null)
  const [knownHash, setKnownHash] = useState('')

  const { pushToast } = useToast()

  const compareResult = useMemo(() => {
    if (!knownHash.trim() || !fileResult) return null
    const value = knownHash.trim().toLowerCase()
    const checks = [
      { label: 'SHA256', value: fileResult.sha256.toLowerCase() },
      { label: 'SHA512', value: fileResult.sha512.toLowerCase() },
      { label: 'MD5', value: (fileResult.md5 || '').toLowerCase() },
    ].filter((item) => item.value)

    const matched = checks.find((item) => item.value === value)
    if (!matched) {
      return { status: 'NOT MATCH', algorithm: null }
    }
    return { status: 'MATCH', algorithm: matched.label }
  }, [knownHash, fileResult])

  async function onGenerateTextHash(event: FormEvent) {
    event.preventDefault()
    if (!textInput.trim()) {
      setTextError('Enter text to generate a hash.')
      return
    }

    setHashingText(true)
    setTextError(null)
    try {
      const output = await hashText(textInput, algorithm)
      setTextResult({
        algorithm,
        hash: output,
        length: output.length,
      })
    } catch {
      setTextError('Unable to generate hash using selected algorithm.')
    } finally {
      setHashingText(false)
    }
  }

  async function onFileSelected(file: File | null) {
    if (!file) {
      setFileResult(null)
      setFileError(null)
      return
    }

    setFileError(null)
    setFileHashing(true)
    try {
      const output = await hashFileInBrowser(file)
      setFileResult(output)
    } catch {
      setFileResult(null)
      setFileError('File hashing failed in browser. Try another file.')
    } finally {
      setFileHashing(false)
    }
  }

  function onClearText() {
    setTextInput('')
    setTextResult(null)
    setTextError(null)
  }

  function onDownloadReport() {
    if (!fileResult) return
    const report = [
      'CyberShield File Hash Report',
      `Generated: ${new Date().toLocaleString()}`,
      '',
      `File: ${fileResult.fileName}`,
      `Size: ${formatBytes(fileResult.fileSize)} (${fileResult.fileSize} bytes)`,
      '',
      `SHA256: ${fileResult.sha256}`,
      `SHA512: ${fileResult.sha512}`,
      `MD5: ${fileResult.md5 || 'N/A'}`,
      '',
      knownHash.trim() ? `Known Hash: ${knownHash.trim()}` : '',
      compareResult ? `Compare Result: ${compareResult.status}${compareResult.algorithm ? ` (${compareResult.algorithm})` : ''}` : '',
    ]
      .filter(Boolean)
      .join('\n')

    downloadTextReport(`hash-report-${fileResult.fileName}.txt`, report)
    pushToast('Hash report downloaded', 'success')
  }

  return (
    <PageWrapper>
      <div className="max-w-6xl mx-auto px-4 sm:px-6 pt-28 pb-20 space-y-5">
        <ToolHeader
          icon={Hash}
          title="Hash Generator + File Hash Calculator"
          description="Generate cryptographic hashes for text and files directly in your browser. No content leaves your device."
        />

        <ResultCard title="Text Hashing" description="Generate hashes for any UTF-8 text input.">
          <form onSubmit={onGenerateTextHash} className="space-y-3">
            <textarea
              value={textInput}
              onChange={(event) => setTextInput(event.target.value)}
              rows={7}
              placeholder="Paste text to hash"
              className="cyber-input w-full rounded-xl px-4 py-3 text-sm font-mono"
            />

            <div className="grid sm:grid-cols-[1fr_auto] gap-3 items-end">
              <div>
                <label className="block text-xs text-gray-500 font-mono mb-1.5">Algorithm</label>
                <select
                  value={algorithm}
                  onChange={(event) => setAlgorithm(event.target.value as HashAlgorithm)}
                  className="cyber-input w-full rounded-xl px-3 py-2.5 text-sm font-mono"
                >
                  {TEXT_HASH_ALGORITHMS.map((option) => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </select>
              </div>

              <div className="flex flex-wrap gap-2">
                <button
                  type="submit"
                  disabled={hashingText}
                  className="px-4 py-2.5 rounded-lg bg-[#0d6efd] hover:bg-[#0b5ed7] disabled:opacity-50 text-white text-sm font-semibold"
                >
                  {hashingText ? 'Generating...' : 'Generate Hash'}
                </button>
                <CopyButton value={textResult?.hash || ''} label="Copy Hash" />
                <button
                  type="button"
                  onClick={onClearText}
                  className="px-4 py-2.5 rounded-lg border border-white/15 text-gray-200 text-sm font-semibold hover:bg-white/5"
                >
                  Clear
                </button>
              </div>
            </div>
          </form>

          {textError && <div className="mt-3"><ErrorAlert message={textError} /></div>}

          <div className="mt-4">
            {textResult ? (
              <HashOutput result={textResult} />
            ) : (
              <EmptyState title="No Hash Generated" description="Enter text and click Generate Hash to see results." />
            )}
          </div>
        </ResultCard>

        <ResultCard title="File Hashing" description="Files are hashed locally using browser APIs. No upload to server.">
          <div className="space-y-3">
            <label className="block text-xs text-gray-500 font-mono">Select file</label>
            <label className="rounded-xl border border-dashed border-white/20 bg-white/3 px-4 py-5 flex items-center gap-3 cursor-pointer hover:bg-white/5 transition-colors">
              <FileUp size={16} className="text-[#6ea8fe]" />
              <span className="text-sm text-gray-200 font-mono">Choose file to calculate SHA256 / SHA512 / MD5</span>
              <input
                type="file"
                className="hidden"
                onChange={(event) => onFileSelected(event.target.files?.[0] || null)}
              />
            </label>

            {fileHashing && <p className="text-xs text-gray-500 font-mono">Calculating file hashes...</p>}
            {fileError && <ErrorAlert message={fileError} />}

            {fileResult ? (
              <div className="space-y-3">
                <div className="grid sm:grid-cols-2 gap-2">
                  <div className="rounded-lg border border-white/10 bg-white/3 px-3 py-2 text-sm text-gray-200 font-mono flex items-center gap-2">
                    <FileDigit size={14} className="text-[#6ea8fe]" />
                    {fileResult.fileName}
                  </div>
                  <div className="rounded-lg border border-white/10 bg-white/3 px-3 py-2 text-sm text-gray-300 font-mono flex items-center gap-2">
                    <Scale size={14} className="text-gray-400" />
                    {formatBytes(fileResult.fileSize)}
                  </div>
                </div>

                <div className="space-y-2">
                  {[
                    { label: 'SHA256', value: fileResult.sha256 },
                    { label: 'SHA512', value: fileResult.sha512 },
                    { label: 'MD5', value: fileResult.md5 || 'N/A' },
                  ].map((row) => (
                    <div key={row.label} className="rounded-lg border border-white/10 bg-white/3 p-3">
                      <div className="flex items-center justify-between gap-3 mb-1.5">
                        <span className="text-xs text-gray-500 font-mono">{row.label}</span>
                        <CopyButton value={row.value === 'N/A' ? '' : row.value} label="Copy" />
                      </div>
                      <div className="text-sm text-gray-200 font-mono break-all">{row.value}</div>
                    </div>
                  ))}
                </div>

                <div className="rounded-lg border border-white/10 bg-white/3 p-3 space-y-2">
                  <label className="block text-xs text-gray-500 font-mono">Compare with known hash</label>
                  <input
                    value={knownHash}
                    onChange={(event) => setKnownHash(event.target.value)}
                    placeholder="Paste expected hash"
                    className="cyber-input w-full rounded-lg px-3 py-2 text-sm font-mono"
                  />
                  {compareResult && (
                    <div className={`inline-flex text-xs font-mono px-2 py-1 rounded border ${compareResult.status === 'MATCH' ? 'text-green-300 border-green-500/30 bg-green-500/10' : 'text-red-300 border-red-500/30 bg-red-500/10'}`}>
                      {compareResult.status}
                      {compareResult.algorithm ? ` (${compareResult.algorithm})` : ''}
                    </div>
                  )}
                </div>

                <button
                  type="button"
                  onClick={onDownloadReport}
                  className="px-4 py-2 rounded-lg border border-[#0d6efd]/35 text-[#6ea8fe] text-sm font-semibold hover:bg-[#0d6efd]/10"
                >
                  Download txt report
                </button>
              </div>
            ) : (
              <EmptyState title="No File Processed" description="Select a file to calculate local hashes." />
            )}
          </div>
        </ResultCard>
      </div>
    </PageWrapper>
  )
}
