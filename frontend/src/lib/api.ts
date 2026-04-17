import type {
  PhishingResult,
  IPResult,
  SSLResult,
  WhoisResult,
  DNSLookupResult,
  DNSLookupProResult,
  SubdomainScanResult,
  SubdomainFinderProResult,
  SubdomainScanMode,
  PortScanResult,
  AdvancedScanResult,
  HeaderAnalysisResult,
  TechStackResult,
  EmailAnalyzerResult,
  EmailAnalyzerAdvancedResult,
  UnifiedReconJobStatus,
  UnifiedReconResult,
  UnifiedReconScanMode,
} from '../types'

// Use environment variable for API base URL, fall back to relative path
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || ''
const BASE = API_BASE_URL ? `${API_BASE_URL}/api` : '/api'

async function post<T>(path: string, body: Record<string, unknown>): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  
  // Handle empty responses
  const text = await res.text()
  if (!text) {
    throw new Error('Server returned an empty response')
  }
  
  let data
  try {
    data = JSON.parse(text)
  } catch {
    throw new Error('Server returned invalid JSON response')
  }
  
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`)
  return data as T
}

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`)

  const text = await res.text()
  if (!text) {
    throw new Error('Server returned an empty response')
  }

  let data
  try {
    data = JSON.parse(text)
  } catch {
    throw new Error('Server returned invalid JSON response')
  }

  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`)
  return data as T
}

export const checkUrl = (url: string) =>
  post<PhishingResult>('/check-url', { url })

export const checkIp = (ip: string) =>
  post<IPResult>('/check-ip', { ip })

export const checkSsl = (domain: string) =>
  post<SSLResult>('/check-ssl', { domain })

export const whoisLookup = (domain: string) =>
  post<WhoisResult>('/whois-lookup', { domain })

export const dnsLookup = (domain: string) =>
  post<DNSLookupResult>('/dns-lookup', { domain })

export const dnsLookupPro = (target: string) =>
  post<DNSLookupProResult>('/dns-lookup-pro', { target })

export const subdomainScan = (domain: string) =>
  post<SubdomainScanResult>('/subdomain-scan', { domain })

export const subdomainFinderPro = (target: string, scan_mode: SubdomainScanMode = 'standard') =>
  post<SubdomainFinderProResult>('/subdomain-finder-pro', { target, scan_mode })

export const portScan = (target: string) =>
  post<PortScanResult>('/port-scan', { target })

export const serviceDetect = (target: string) =>
  post<{ target: string; resolved_ip: string; services: Array<{ port: number; service: string; banner?: string | null }> }>('/service-detect', { target })

export const advancedScan = (target: string, scan_type: 'quick' | 'full' | 'web' | 'custom', custom_range = '') =>
  post<AdvancedScanResult>('/advanced-scan', { target, scan_type, custom_range })

export const headerAnalysis = (url: string) =>
  post<HeaderAnalysisResult>('/http-header-audit', { target: url })

export const techStackAnalysis = (target: string) =>
  post<TechStackResult>('/tech-stack-detect', { target })

export const emailHeaderAnalysis = (raw_header: string) =>
  post<EmailAnalyzerResult>('/email-analyzer', { raw_header })

export const emailHeaderAnalysisAdvanced = (raw_header: string) =>
  post<EmailAnalyzerAdvancedResult>('/email-analyzer-advanced', { raw_header })

export const unifiedReconScan = (target: string, scan_mode: UnifiedReconScanMode = 'standard') =>
  post<UnifiedReconResult>('/unified-recon', { target, scan_mode })

export const startUnifiedReconScan = (target: string, scan_mode: UnifiedReconScanMode = 'standard') =>
  post<UnifiedReconJobStatus>('/unified-recon/start', { target, scan_mode })

export const getUnifiedReconScanStatus = (job_id: string) =>
  get<UnifiedReconJobStatus>(`/unified-recon/status/${encodeURIComponent(job_id)}`)

export async function downloadUnifiedReconPdf(payload: {
  result?: UnifiedReconResult
  target?: string
  scan_mode?: UnifiedReconScanMode
}): Promise<Blob> {
  const res = await fetch(`${BASE}/download-unified-recon-pdf`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })

  if (!res.ok) {
    const text = await res.text()
    let message = `Request failed (${res.status})`
    try {
      const parsed = JSON.parse(text)
      message = parsed.error || message
    } catch {
      if (text) message = text
    }
    throw new Error(message)
  }

  return res.blob()
}
