export interface VendorEntry {
  name: string
  result: string
}

export interface PhishingResult {
  verdict: string
  final_score: number
  severity: string
  security_recommendation: string
  score_breakdown: {
    custom_weight: number
    api_weight: number
    custom_contribution: number
    api_contribution: number
  }
  custom_score: number
  api_score: number
  detection_reasons: string[]
  analysis_features: Record<string, unknown>
  domain_info: {
    registrar: string
    creation_date: string
    expiration_date: string
    last_updated: string
    name_servers: string[]
    domain_status: string
    registrant_country: string
    registrant_organization: string
  }
  domain: string
  analyzed_url: string
  urlhaus?: {
    enabled: boolean
    matched: boolean
    query_status: string
    message?: string
    id?: string
    urlhaus_reference?: string
    url_status?: string
    host?: string
    date_added?: string
    last_online?: string | null
    threat?: string
    reporter?: string
    larted?: string
    takedown_time_seconds?: number | null
    blacklists?: {
      surbl?: string
      spamhaus_dbl?: string
    }
    tags?: string[]
    payload_count?: number
    payloads?: Array<{
      firstseen?: string
      filename?: string | null
      file_type?: string
      response_size?: string
      response_md5?: string
      response_sha256?: string
      signature?: string | null
      imphash?: string
      ssdeep?: string
      tlsh?: string
      magika?: string
      virustotal?: {
        result?: string
        percent?: string
        link?: string
      } | null
    }>
  }
  vendor_data: {
    malicious: VendorEntry[]
    suspicious: VendorEntry[]
    clean: string[]
    stats: {
      malicious: number
      suspicious: number
      harmless: number
      undetected: number
    }
  }
}

export interface IPResult {
  verdict: string
  final_score: number
  severity: string
  security_recommendation: string
  custom_score: number
  api_score: number
  score_breakdown: {
    custom_weight: number
    api_weight: number
    custom_contribution: number
    api_contribution: number
  }
  detection_reasons: string[]
  risk_factors: Array<{
    indicator: string
    severity: string
    description: string
    risk_points: number
  }>
  threat_categories: string[]
  country: string
  region: string
  city: string
  isp: string
  asn: string
  connection_type: string
  latitude: number | null
  longitude: number | null
  timezone: string
  postal_code: string
  vendor_data: {
    malicious_vendors: VendorEntry[]
    suspicious_vendors: VendorEntry[]
    clean_vendors: string[]
    malicious_count: number
    suspicious_count: number
    clean_count: number
    total_vendors: number
  }
  vendor_summary: {
    malicious: number
    suspicious: number
    clean: number
    total_analyzed: number
  }
  valid: boolean
  ip_version: string
}

export interface SSLResult {
  status: string
  issuer: string
  subject: string
  valid_from: string
  valid_until: string
  days_until_expiry: number
  is_valid: boolean
  message?: string
}

export interface WhoisResult {
  domainName: string
  domainNameExt: string
  status: string
  estimatedDomainAge: string | number
  contactEmail: string
  createdDate: string
  updatedDate: string
  expiresDate: string
  registrarName: string
  registrarIANAID: string
  whoisServer: string
  nameServers: string[]
  registrant: Record<string, string>
  administrativeContact: Record<string, string>
  technicalContact: Record<string, string>
}

export interface DNSLookupResult {
  domain: string
  records: {
    A: string[]
    AAAA: string[]
    CNAME: string[]
    MX: string[]
    NS: string[]
    TXT: string[]
    SOA: string[]
    CAA: string[]
    DMARC: string[]
    SPF: string[]
  }
}

export interface SubdomainScanResult {
  domain: string
  count: number
  found: Array<{
    subdomain: string
    ip: string
  }>
}

export interface PortScanResult {
  target: string
  resolved_ip: string
  open_ports: number[]
  ports: Array<{
    port: number
    status: 'open' | 'closed'
  }>
}

export interface HeaderAnalysisResult {
  url: string
  status_code: number
  headers: Record<string, string>
  missing_security_headers: string[]
}

export interface TechStackResult {
  url: string
  technologies: string[]
  categorized: Record<string, string[]>
}

export interface EmailAnalyzerResult {
  basic_info: {
    from: string
    to: string
    subject: string
    date: string
    return_path: string
    message_id: string
  }
  authentication: {
    spf: string
    dkim: string
    dmarc: string
  }
  ip_route: string[]
  issues: string[]
}

export interface EmailAnalyzerAdvancedResult {
  basic_info: {
    from: string
    to: string
    subject: string
    date: string
    return_path: string
    reply_to: string
    message_id: string
  }
  authentication: {
    spf: string
    dkim: string
    dmarc: string
    spf_domain: string
    dkim_domain: string
  }
  spoofing_checks: string[]
  ip_route: string[]
  ip_analysis: Array<{
    ip: string
    status: string
    malicious_count?: number
    suspicious_count?: number
  }>
  phishing_indicators: string[]
  domain_analysis: string
  time_delay_analysis: {
    hop_delays_seconds: number[]
    max_delay_seconds: number
    suspicious: boolean
    notes: string
  }
  issues: string[]
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH'
  risk_score: number
}
