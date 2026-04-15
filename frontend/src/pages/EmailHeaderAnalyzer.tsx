import { useState, FormEvent } from 'react'
import { MailCheck, ShieldCheck, ShieldX, AlertTriangle, Route, Search, Radar, ShieldAlert, Bot, Clock3, Download } from 'lucide-react'
import PageWrapper from '../components/ui/PageWrapper'
import LoadingSpinner from '../components/ui/LoadingSpinner'
import { emailHeaderAnalysisAdvanced } from '../lib/api'
import type { EmailAnalyzerAdvancedResult } from '../types'

const SAMPLE_HEADER = `Received: from mail.example.com (203.0.113.5)
Received: by mx.google.com with SMTP id abc123; Tue, 14 Apr 2026 10:12:58 +0000
From: test@example.com
To: user@gmail.com
Subject: Urgent Verify Login Alert
Date: Tue, 14 Apr 2026 10:12:55 +0000
Return-Path: <bounce@alerts-example.xyz>
Reply-To: support@helpdesk-example.xyz
Message-ID: <abc123@example.com>
Authentication-Results: mx.google.com; spf=fail smtp.mailfrom=alerts-example.xyz; dkim=fail header.d=alerts-example.xyz; dmarc=fail`

function authBadge(value: string) {
  const normalized = (value || '').toLowerCase()
  if (normalized === 'pass') {
    return {
      text: 'Pass',
      icon: <ShieldCheck size={14} className="text-green-400" />,
      className: 'text-green-400 bg-green-500/10 border-green-500/30',
    }
  }
  if (normalized === 'fail') {
    return {
      text: 'Fail',
      icon: <ShieldX size={14} className="text-red-400" />,
      className: 'text-red-400 bg-red-500/10 border-red-500/30',
    }
  }
  return {
    text: value || 'Missing',
    icon: <AlertTriangle size={14} className="text-yellow-400" />,
    className: 'text-yellow-300 bg-yellow-500/10 border-yellow-500/30',
  }
}

export default function EmailHeaderAnalyzer() {
  const [rawHeader, setRawHeader] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<EmailAnalyzerAdvancedResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [downloadingPdf, setDownloadingPdf] = useState(false)

  async function onSubmit(e: FormEvent) {
    e.preventDefault()
    if (!rawHeader.trim()) {
      setError('Paste raw email headers to analyze.')
      setResult(null)
      return
    }
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      setResult(await emailHeaderAnalysisAdvanced(rawHeader.trim()))
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Email header analysis failed')
    } finally {
      setLoading(false)
    }
  }

  async function downloadPdfReport() {
    if (!rawHeader.trim()) {
      setError('Paste raw email headers before downloading report.')
      return
    }

    setDownloadingPdf(true)
    setError(null)
    try {
      const response = await fetch('/api/download-email-analysis-pdf', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ raw_header: rawHeader.trim() }),
      })

      if (!response.ok) {
        let message = `Request failed (${response.status})`
        try {
          const json = await response.json()
          message = json.error || message
        } catch {
          // ignore parse error
        }
        throw new Error(message)
      }

      const blob = await response.blob()
      const url = window.URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = 'email-threat-analysis-report.pdf'
      document.body.appendChild(link)
      link.click()
      link.remove()
      window.URL.revokeObjectURL(url)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to download PDF report')
    } finally {
      setDownloadingPdf(false)
    }
  }

  return (
    <PageWrapper>
      <div className="max-w-5xl mx-auto px-4 sm:px-6 pt-28 pb-20">
        <div className="mb-8 flex items-center gap-2.5">
          <div className="p-2 rounded-lg bg-[#0d6efd]/10 border border-[#0d6efd]/20">
            <MailCheck size={18} className="text-[#0d6efd]" />
          </div>
          <h1 className="text-2xl font-bold text-white">Email Forensics & Threat Analysis</h1>
        </div>

        <form onSubmit={onSubmit} className="glass-card rounded-2xl p-5 mb-6 space-y-3">
          <textarea
            value={rawHeader}
            onChange={(e) => setRawHeader(e.target.value)}
            placeholder="Paste complete raw email headers here..."
            rows={12}
            className="cyber-input w-full px-4 py-3 rounded-xl text-sm font-mono leading-6 resize-y"
          />
          <div className="flex flex-wrap gap-3">
            <button className="flex items-center gap-2 px-6 py-3 bg-[#0d6efd] hover:bg-[#0b5ed7] !text-white font-semibold rounded-xl text-sm">
              <Search size={16} />
              Analyze Email
            </button>
            <button
              type="button"
              onClick={() => setRawHeader(SAMPLE_HEADER)}
              className="px-4 py-3 rounded-xl text-sm border border-white/15 text-gray-300 hover:text-white hover:bg-white/5"
            >
              Load Sample Header
            </button>
            <button
              type="button"
              onClick={downloadPdfReport}
              disabled={downloadingPdf || !rawHeader.trim()}
              className="px-4 py-3 rounded-xl text-sm border border-[#0d6efd]/35 text-[#0d6efd] hover:bg-[#0d6efd]/10 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
            >
              <Download size={15} />
              {downloadingPdf ? 'Generating PDF...' : 'Download PDF'}
            </button>
          </div>
        </form>

        {loading && <div className="glass-card rounded-2xl"><LoadingSpinner label="Analyzing email forensics signals..." /></div>}
        {error && <div className="glass-card rounded-2xl p-5 border border-red-500/25 bg-red-500/5 text-red-400 text-sm font-mono">{error}</div>}

        {result && (
          <div className="space-y-5">
            <div className="glass-card rounded-2xl p-5">
              <h2 className="text-lg font-semibold text-white mb-4">📧 Email Analysis</h2>
              <div className="grid md:grid-cols-2 gap-3 text-sm font-mono">
                <div><span className="text-gray-500">From:</span> <span className="text-gray-200 break-all">{result.basic_info.from || '-'}</span></div>
                <div><span className="text-gray-500">To:</span> <span className="text-gray-200 break-all">{result.basic_info.to || '-'}</span></div>
                <div><span className="text-gray-500">Subject:</span> <span className="text-gray-200 break-all">{result.basic_info.subject || '-'}</span></div>
                <div><span className="text-gray-500">Date:</span> <span className="text-gray-200 break-all">{result.basic_info.date || '-'}</span></div>
                <div><span className="text-gray-500">Return-Path:</span> <span className="text-gray-200 break-all">{result.basic_info.return_path || '-'}</span></div>
                <div><span className="text-gray-500">Reply-To:</span> <span className="text-gray-200 break-all">{result.basic_info.reply_to || '-'}</span></div>
                <div><span className="text-gray-500">Message-ID:</span> <span className="text-gray-200 break-all">{result.basic_info.message_id || '-'}</span></div>
              </div>
            </div>

            <div className="glass-card rounded-2xl p-5">
              <h3 className="text-sm font-semibold text-white mb-3">🔐 Authentication</h3>
              <div className="grid sm:grid-cols-3 gap-3">
                {(['spf', 'dkim', 'dmarc'] as const).map((key) => {
                  const meta = authBadge(result.authentication[key])
                  return (
                    <div key={key} className={`rounded-xl border px-3 py-2 ${meta.className}`}>
                      <div className="text-xs uppercase tracking-wide mb-1">{key}</div>
                      <div className="flex items-center gap-1.5 text-sm font-semibold">
                        {meta.icon}
                        {meta.text}
                      </div>
                    </div>
                  )
                })}
              </div>
              <div className="mt-3 text-xs text-gray-400 font-mono">
                SPF Domain: {result.authentication.spf_domain || '-'} | DKIM d=: {result.authentication.dkim_domain || '-'}
              </div>
            </div>

            <div className="glass-card rounded-2xl p-5">
              <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
                <ShieldAlert size={15} className="text-[#0d6efd]" />
                🕵 Spoofing Checks
              </h3>
              {result.spoofing_checks.length > 0 ? (
                <ul className="space-y-2">
                  {result.spoofing_checks.map((issue) => (
                    <li key={issue} className="text-sm text-yellow-300 font-mono bg-yellow-500/10 border border-yellow-500/25 rounded-lg px-3 py-2">
                      • {issue}
                    </li>
                  ))}
                </ul>
              ) : (
                <div className="text-sm text-green-400 font-mono">No major sender identity mismatch detected.</div>
              )}
            </div>

            <div className="glass-card rounded-2xl p-5">
              <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
                <Route size={15} className="text-[#0d6efd]" />
                🌍 Email Route
              </h3>
              {result.ip_route.length > 0 ? (
                <div className="text-sm text-gray-200 font-mono break-all">
                  {result.ip_route.join(' -> ')}
                </div>
              ) : (
                <div className="text-sm text-gray-500 font-mono">No routing IPs found in Received headers.</div>
              )}
            </div>

            <div className="glass-card rounded-2xl p-5">
              <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
                <Radar size={15} className="text-[#0d6efd]" />
                🚨 IP Analysis
              </h3>
              {result.ip_analysis.length > 0 ? (
                <div className="space-y-2">
                  {result.ip_analysis.map((entry) => (
                    <div key={entry.ip} className="text-sm font-mono rounded-lg px-3 py-2 border border-white/10 bg-white/5">
                      <span className="text-gray-200">{entry.ip}</span>
                      <span className={`ml-2 ${
                        entry.status === 'malicious'
                          ? 'text-red-400'
                          : entry.status === 'suspicious'
                          ? 'text-yellow-300'
                          : 'text-green-400'
                      }`}>
                        → {entry.status.toUpperCase()}
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-sm text-gray-500 font-mono">No route IP reputation data available.</div>
              )}
            </div>

            <div className="glass-card rounded-2xl p-5">
              <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
                <Bot size={15} className="text-[#0d6efd]" />
                🎣 Phishing Indicators
              </h3>
              {result.phishing_indicators.length > 0 ? (
                <ul className="space-y-2">
                  {result.phishing_indicators.map((indicator) => (
                    <li key={indicator} className="text-sm text-yellow-300 font-mono bg-yellow-500/10 border border-yellow-500/25 rounded-lg px-3 py-2">
                      • {indicator}
                    </li>
                  ))}
                </ul>
              ) : (
                <div className="text-sm text-green-400 font-mono">No strong phishing keyword/domain indicators found.</div>
              )}
              <div className="mt-3 text-xs text-gray-400 font-mono">{result.domain_analysis}</div>
            </div>

            <div className="glass-card rounded-2xl p-5">
              <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
                <Clock3 size={15} className="text-[#0d6efd]" />
                ⏱ Relay Delay Analysis
              </h3>
              <div className="text-sm text-gray-200 font-mono mb-1">Max Delay: {result.time_delay_analysis.max_delay_seconds}s</div>
              <div className="text-xs text-gray-400 font-mono">{result.time_delay_analysis.notes}</div>
            </div>

            <div className="glass-card rounded-2xl p-5">
              <h3 className="text-sm font-semibold text-white mb-3">⚠ Issues</h3>
              {result.issues.length > 0 ? (
                <ul className="space-y-2">
                  {result.issues.map((issue) => (
                    <li key={issue} className="text-sm text-red-300 font-mono bg-red-500/10 border border-red-500/25 rounded-lg px-3 py-2">
                      • {issue}
                    </li>
                  ))}
                </ul>
              ) : (
                <div className="text-sm text-green-400 font-mono">No high-risk authentication issues detected.</div>
              )}
            </div>

            <div
              className={`glass-card rounded-2xl p-5 border ${
                result.risk_level === 'HIGH'
                  ? 'border-red-500/35 bg-red-500/10'
                  : result.risk_level === 'MEDIUM'
                  ? 'border-yellow-500/35 bg-yellow-500/10'
                  : 'border-green-500/35 bg-green-500/10'
              }`}
            >
              <div className="text-sm text-gray-300 font-mono">🔥 Overall Risk</div>
              <div
                className={`text-xl font-bold mt-1 ${
                  result.risk_level === 'HIGH'
                    ? 'text-red-400'
                    : result.risk_level === 'MEDIUM'
                    ? 'text-yellow-300'
                    : 'text-green-400'
                }`}
              >
                {result.risk_level}
              </div>
              <div className="text-xs text-gray-400 font-mono mt-1">Risk Score: {result.risk_score}/100</div>
            </div>
          </div>
        )}
      </div>
    </PageWrapper>
  )
}
