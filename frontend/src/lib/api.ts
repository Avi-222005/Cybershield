import type {
  PhishingResult,
  IPResult,
  SSLResult,
  WhoisResult,
  DNSLookupResult,
  SubdomainScanResult,
  PortScanResult,
  HeaderAnalysisResult,
  TechStackResult,
  EmailAnalyzerResult,
  EmailAnalyzerAdvancedResult,
} from '../types'

// Use environment variable for API base URL, fall back to relative path
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || ''
const BASE = API_BASE_URL ? `${API_BASE_URL}/api` : '/api'

async function post<T>(path: string, body: Record<string, string>): Promise<T> {
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

export const subdomainScan = (domain: string) =>
  post<SubdomainScanResult>('/subdomain-scan', { domain })

export const portScan = (target: string) =>
  post<PortScanResult>('/port-scan', { target })

export const serviceDetect = (target: string) =>
  post<{ target: string; resolved_ip: string; services: Array<{ port: number; service: string; banner?: string | null }> }>('/service-detect', { target })

export const headerAnalysis = (url: string) =>
  post<HeaderAnalysisResult>('/header-analysis', { url })

export const techStackAnalysis = (url: string) =>
  post<TechStackResult>('/tech-stack', { url })

export const emailHeaderAnalysis = (raw_header: string) =>
  post<EmailAnalyzerResult>('/email-analyzer', { raw_header })

export const emailHeaderAnalysisAdvanced = (raw_header: string) =>
  post<EmailAnalyzerAdvancedResult>('/email-analyzer-advanced', { raw_header })
