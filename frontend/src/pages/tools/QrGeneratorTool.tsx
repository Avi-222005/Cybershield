import { useEffect, useMemo, useState } from 'react'
import { Download, QrCode, RotateCcw } from 'lucide-react'
import QRCode from 'qrcode'
import PageWrapper from '../../components/ui/PageWrapper'
import {
  CopyButton,
  EmptyState,
  ErrorAlert,
  ResultCard,
  ToolHeader,
} from '../../components/ui/tools'
import { useToast } from '../../context/ToastContext'

type ErrorCorrectionLevel = 'L' | 'M' | 'Q' | 'H'

const PRESETS = [
  { label: 'Website URL', value: 'https://example.com' },
  { label: 'Email', value: 'mailto:security@example.com' },
  { label: 'WiFi', value: 'WIFI:T:WPA;S:MyWiFi;P:StrongPassword123;;' },
  { label: 'Contact', value: 'BEGIN:VCARD\nVERSION:3.0\nFN:CyberShield SOC\nTEL:+1-555-0100\nEMAIL:soc@example.com\nEND:VCARD' },
]

function hexToRgbaHex(hex: string, alpha: number): string {
  const normalized = hex.replace('#', '')
  const safeHex = normalized.length === 3
    ? normalized.split('').map((char) => `${char}${char}`).join('')
    : normalized

  const safeAlpha = Math.max(0, Math.min(1, alpha))
  const alphaHex = Math.round(safeAlpha * 255)
    .toString(16)
    .padStart(2, '0')
  return `#${safeHex}${alphaHex}`
}

export default function QrGeneratorTool() {
  const [input, setInput] = useState('https://cybershield.local')
  const [size, setSize] = useState(320)
  const [margin, setMargin] = useState(2)
  const [errorCorrectionLevel, setErrorCorrectionLevel] = useState<ErrorCorrectionLevel>('M')
  const [foreground, setForeground] = useState('#0d6efd')
  const [background, setBackground] = useState('#ffffff')
  const [backgroundAlpha, setBackgroundAlpha] = useState(100)

  const [qrDataUrl, setQrDataUrl] = useState('')
  const [svgContent, setSvgContent] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [isGenerating, setIsGenerating] = useState(false)

  const { pushToast } = useToast()

  const canGenerate = useMemo(() => input.trim().length > 0, [input])
  const backgroundOpacity = useMemo(() => Math.max(0, Math.min(100, backgroundAlpha)) / 100, [backgroundAlpha])
  const backgroundWithAlpha = useMemo(() => hexToRgbaHex(background, backgroundOpacity), [background, backgroundOpacity])
  const isBackgroundTransparent = backgroundOpacity === 0

  useEffect(() => {
    if (!canGenerate) {
      setQrDataUrl('')
      setSvgContent('')
      setError(null)
      return
    }

    let mounted = true

    async function generateQr() {
      setIsGenerating(true)
      setError(null)
      try {
        const options = {
          errorCorrectionLevel,
          margin,
          width: size,
          color: {
            dark: foreground,
            light: backgroundWithAlpha,
          },
        }

        const [dataUrl, svg] = await Promise.all([
          QRCode.toDataURL(input, options),
          QRCode.toString(input, { ...options, type: 'svg' }),
        ])

        if (!mounted) return
        setQrDataUrl(dataUrl)
        setSvgContent(svg)
      } catch {
        if (!mounted) return
        setError('Unable to generate QR code. Please validate your input and style settings.')
      } finally {
        if (mounted) setIsGenerating(false)
      }
    }

    generateQr()
    return () => {
      mounted = false
    }
  }, [backgroundWithAlpha, canGenerate, errorCorrectionLevel, foreground, input, margin, size])

  function resetDefaults() {
    setInput('https://cybershield.local')
    setSize(320)
    setMargin(2)
    setErrorCorrectionLevel('M')
    setForeground('#0d6efd')
    setBackground('#ffffff')
    setBackgroundAlpha(100)
  }

  function downloadPng() {
    if (!qrDataUrl) return
    const anchor = document.createElement('a')
    anchor.href = qrDataUrl
    anchor.download = 'cybershield-qr.png'
    document.body.appendChild(anchor)
    anchor.click()
    anchor.remove()
    pushToast('QR PNG downloaded', 'success')
  }

  function downloadSvg() {
    if (!svgContent) return
    const blob = new Blob([svgContent], { type: 'image/svg+xml;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = 'cybershield-qr.svg'
    document.body.appendChild(anchor)
    anchor.click()
    anchor.remove()
    URL.revokeObjectURL(url)
    pushToast('QR SVG downloaded', 'success')
  }

  return (
    <PageWrapper>
      <div className="max-w-6xl mx-auto px-4 sm:px-6 pt-28 pb-20 space-y-5">
        <ToolHeader
          icon={QrCode}
          title="QR Generator"
          description="Create high-quality QR codes instantly in your browser. No payload is sent to the server."
        />

        <ResultCard title="QR Content" description="Paste text, URL, or structured payload.">
          <div className="space-y-3">
            <textarea
              value={input}
              onChange={(event) => setInput(event.target.value)}
              rows={6}
              placeholder="Enter text or URL"
              className="cyber-input w-full rounded-xl px-4 py-3 text-sm font-mono"
            />

            <div className="flex flex-wrap gap-2">
              {PRESETS.map((preset) => (
                <button
                  key={preset.label}
                  type="button"
                  onClick={() => setInput(preset.value)}
                  className="px-3 py-1.5 rounded-lg border border-white/15 text-xs font-mono text-gray-200 hover:bg-white/5"
                >
                  {preset.label}
                </button>
              ))}
            </div>

            <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-3">
              <div>
                <label className="block text-xs text-gray-500 font-mono mb-1.5">Error correction</label>
                <select
                  value={errorCorrectionLevel}
                  onChange={(event) => setErrorCorrectionLevel(event.target.value as ErrorCorrectionLevel)}
                  className="cyber-input w-full rounded-lg px-3 py-2 text-sm font-mono"
                >
                  <option value="L">L - Low</option>
                  <option value="M">M - Medium</option>
                  <option value="Q">Q - Quartile</option>
                  <option value="H">H - High</option>
                </select>
              </div>

              <div>
                <label className="block text-xs text-gray-500 font-mono mb-1.5">Size</label>
                <input
                  type="range"
                  min={160}
                  max={720}
                  step={8}
                  value={size}
                  onChange={(event) => setSize(Number(event.target.value))}
                  className="w-full accent-[#0d6efd]"
                />
                <div className="text-xs text-gray-400 font-mono mt-1">{size}px</div>
              </div>

              <div>
                <label className="block text-xs text-gray-500 font-mono mb-1.5">Margin</label>
                <input
                  type="range"
                  min={0}
                  max={8}
                  value={margin}
                  onChange={(event) => setMargin(Number(event.target.value))}
                  className="w-full accent-[#0d6efd]"
                />
                <div className="text-xs text-gray-400 font-mono mt-1">{margin}</div>
              </div>

              <div className="grid grid-cols-2 gap-2">
                <label className="text-xs text-gray-500 font-mono">
                  Foreground
                  <input
                    type="color"
                    value={foreground}
                    onChange={(event) => setForeground(event.target.value)}
                    className="mt-1 w-full h-10 rounded-lg border border-white/15 bg-transparent"
                  />
                </label>
                <label className="text-xs text-gray-500 font-mono">
                  Background
                  <input
                    type="color"
                    value={background}
                    onChange={(event) => setBackground(event.target.value)}
                    className="mt-1 w-full h-10 rounded-lg border border-white/15 bg-transparent"
                  />
                </label>

                <div className="col-span-2 rounded-lg border border-white/10 bg-white/3 px-2.5 py-2">
                  <div className="flex items-center justify-between gap-2 mb-1.5">
                    <label className="text-xs text-gray-500 font-mono">Background alpha</label>
                    <span className="text-xs text-gray-300 font-mono">{backgroundAlpha}%</span>
                  </div>
                  <input
                    type="range"
                    min={0}
                    max={100}
                    value={backgroundAlpha}
                    onChange={(event) => setBackgroundAlpha(Number(event.target.value))}
                    className="w-full accent-[#0d6efd]"
                  />
                  <div className="flex items-center justify-between gap-2 mt-1.5">
                    <span className="text-[11px] text-gray-500 font-mono">0% = transparent background</span>
                    <button
                      type="button"
                      onClick={() => setBackgroundAlpha(0)}
                      className="text-[11px] font-mono px-2 py-1 rounded border border-white/15 text-gray-300 hover:bg-white/5"
                    >
                      Set Transparent
                    </button>
                  </div>
                </div>
              </div>
            </div>

            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                onClick={resetDefaults}
                className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg border border-white/15 text-gray-200 text-xs font-mono hover:bg-white/5"
              >
                <RotateCcw size={12} />
                Reset
              </button>
              <CopyButton value={input} label="Copy Payload" successMessage="QR payload copied" />
            </div>
          </div>
        </ResultCard>

        <ResultCard title="Generated QR" description="Scan preview and export options.">
          {error && <ErrorAlert message={error} />}

          {!canGenerate ? (
            <EmptyState title="No QR Content" description="Enter text or URL to generate a QR code." />
          ) : isGenerating ? (
            <div className="rounded-xl border border-white/10 bg-white/3 p-6 text-center text-sm text-gray-400 font-mono">
              Generating QR code...
            </div>
          ) : qrDataUrl ? (
            <div className="space-y-4">
              <div
                className="rounded-xl border border-white/10 p-4 flex justify-center"
                style={{
                  backgroundColor: isBackgroundTransparent ? 'rgba(255,255,255,0.03)' : 'rgba(255,255,255,0.03)',
                  backgroundImage: isBackgroundTransparent
                    ? 'linear-gradient(45deg, rgba(255,255,255,0.08) 25%, transparent 25%), linear-gradient(-45deg, rgba(255,255,255,0.08) 25%, transparent 25%), linear-gradient(45deg, transparent 75%, rgba(255,255,255,0.08) 75%), linear-gradient(-45deg, transparent 75%, rgba(255,255,255,0.08) 75%)'
                    : 'none',
                  backgroundSize: isBackgroundTransparent ? '14px 14px' : 'auto',
                  backgroundPosition: isBackgroundTransparent ? '0 0, 0 7px, 7px -7px, -7px 0' : '0 0',
                }}
              >
                <img
                  src={qrDataUrl}
                  alt="Generated QR"
                  className="max-w-full h-auto rounded"
                  style={{ width: Math.min(size, 420), height: 'auto' }}
                />
              </div>

              {isBackgroundTransparent && (
                <div className="text-xs text-cyan-300 font-mono">
                  Transparent background enabled (alpha 0%).
                </div>
              )}

              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  onClick={downloadPng}
                  className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg bg-[#0d6efd] hover:bg-[#0b5ed7] text-white text-xs font-semibold"
                >
                  <Download size={12} />
                  Download PNG
                </button>
                <button
                  type="button"
                  onClick={downloadSvg}
                  className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg border border-[#0d6efd]/35 text-[#6ea8fe] text-xs font-semibold hover:bg-[#0d6efd]/10"
                >
                  <Download size={12} />
                  Download SVG
                </button>
              </div>
            </div>
          ) : (
            <EmptyState title="QR Preview Unavailable" description="Adjust input and settings to generate a QR code." />
          )}
        </ResultCard>
      </div>
    </PageWrapper>
  )
}
