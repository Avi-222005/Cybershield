export interface VendorEntry {
  name: string
  result: string
}

export interface AnalysisFeatures {
  url_length: number
  uses_ip: boolean
  subdomain_count: number
  special_chars?: { is_suspicious: boolean }
  suspicious_keywords_found: number
  suspicious_keywords_list?: string[]
  https_in_domain: boolean
  uses_https: boolean
  is_http_only: boolean
  is_url_shortener: boolean
  high_risk_tld: boolean
  tld_name?: string
  dot_count: number
  excessive_dots: boolean
  brand_spoofing: boolean
  brands_found?: string[]
  has_punycode: boolean
  path_depth: number
  path_depth_suspicious: boolean
  [key: string]: any
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
  analysis_features: AnalysisFeatures
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
  registrarURL?: string
  whoisServer: string
  dnssec?: string
  privacyProtection?: string
  lookupSources?: string[]
  lookupNotes?: string[]
  ips?: string[]
  nameServers: string[]
  nameServerIPs?: Record<string, string[]>
  domainAvailability?: string
  audit?: {
    createdDate: string
    updatedDate: string
  }
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

export interface DNSLookupProResult {
  target: string
  normalized_domain: string
  root_domain: string
  grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F'
  score: number
  dnssec: {
    enabled: boolean
    ds_present: boolean
    dnskey_present: boolean
    ds_records: string[]
    dnskey_count: number
  }
  spf: {
    present: boolean
    record: string | null
    policy: string
    risk: string
    includes: number
    issues: string[]
  }
  dmarc: {
    present: boolean
    record: string | null
    policy: string
    enforcement: string
    rua: string | null
    ruf: string | null
    pct: string | null
    issues: string[]
  }
  dkim: {
    status: string
    selectors_found: string[]
  }
  mx: {
    count: number
    records: Array<{ priority: number; host: string }>
    providers: string[]
    issues: string[]
  }
  ns: {
    count: number
    records: string[]
    providers: string[]
    issues: string[]
  }
  caa: {
    present: boolean
    records: string[]
    authorized_cas: string[]
    issues: string[]
  }
  soa: {
    present: boolean
    record: {
      primary_ns: string
      responsible: string
      serial: string
      refresh: string
      retry: string
      expire: string
      minimum: string
    } | null
    issues: string[]
  }
  infrastructure: {
    provider_guess: string
    a_count: number
    aaaa_count: number
    ptr_count: number
  }
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
    PTR: string[]
  }
  issues: string[]
  recommendations: string[]
  generated_at: string
}

export interface SubdomainScanResult {
  domain: string
  count: number
  found: Array<{
    subdomain: string
    ip: string
  }>
}

export interface SubdomainFinderProHost {
  host: string
  ip: string | null
  status: 'Live' | 'Dead' | 'Redirect' | 'Timeout'
  http_code: number | null
  title: string
  server: string
  tech: string[]
  redirect?: boolean
  final_url?: string
  risk: 'LOW' | 'MEDIUM' | 'HIGH'
  issues: string[]
  sources: string[]
  dns: {
    a: string[]
    aaaa: string[]
    cname: string[]
  }
  takeover_possible: boolean
}

export type SubdomainScanMode = 'light' | 'standard' | 'deep'

export interface HistoricalCandidate {
  host: string
  sources: string[]
  risk: 'LOW' | 'MEDIUM' | 'HIGH'
  issues: string[]
  reason: string
}

export interface SubdomainFinderProResult {
  target: string
  scan_mode: SubdomainScanMode
  grade: 'A+' | 'B' | 'C' | 'D' | 'F'
  grade_label: string
  score: number
  sources_used: string[]
  source_stats: Record<string, number>
  total_found: number
  validated: number
  historical_unresolved: number
  live_hosts: number
  high_risk: number
  wildcard_dns: boolean
  subdomains: SubdomainFinderProHost[]
  historical_candidates: HistoricalCandidate[]
  recommendations: string[]
  source_errors: Record<string, string>
  cached: boolean
  generated_at: string
}

export interface PortScanResult {
  target: string
  resolved_ip: string
  scan_protocol: ScanProtocol
  open_ports: number[]
  ports: Array<{
    port: number
    status: 'open' | 'closed' | 'filtered'
  }>
}

export type AdvancedScanType = 'quick' | 'full' | 'web' | 'custom'
export type ScanProtocol = 'tcp' | 'udp'

export interface AdvancedPortResult {
  port: number
  protocol?: ScanProtocol
  status: 'open' | 'closed' | 'filtered'
  service: string
  banner?: string | null
  product?: string | null
  version?: string | null
  risky: boolean
  issue?: string | null
}

export interface AdvancedScanResult {
  target: string
  resolved_ip: string
  scan_type: AdvancedScanType
  scan_protocol: ScanProtocol
  ports_scanned: number
  open_ports: number
  closed_ports: number
  filtered_ports: number
  services: string[]
  os_guess: string
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH'
  issues: string[]
  summary: string
  warning: string
  duration_ms: number
  results: AdvancedPortResult[]
  open_port_details: AdvancedPortResult[]
}

export interface HeaderAnalysisResult {
  target: string
  final_url: string
  redirected_url: string | null
  redirect_chain: string[]
  protocol_used: string
  status_code: number
  response_time_ms: number
  grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F'
  score: number
  https_enforced: boolean
  headers_present: string[]
  headers_missing: string[]
  weak_headers: Array<{
    header: string
    reason: string
    value: string
  }>
  security_headers: Array<{
    header: string
    status: 'Present' | 'Missing' | 'Weak'
    notes: string
  }>
  cookies: Array<{
    cookie_name: string
    httponly: boolean
    secure: boolean
    samesite: string
    session_cookie: boolean
    long_expiry: boolean
    risk: string
  }>
  cookie_risk_count: number
  leaks: string[]
  cache_security: {
    cache_control: string
    pragma: string
    expires: string
    issues: string[]
  }
  issues: string[]
  recommendations: string[]
  headers: Record<string, string>
}

export interface TechStackDetectedTechnology {
  name: string
  normalized_name: string
  version: string
  confidence: number
  categories: string[]
  website?: string | null
  section?: string
  signals?: string[]
}

export interface TechStackSummary {
  total: number
  high_confidence: number
  frameworks: string[]
  servers: string[]
  security: string[]
}

export interface TechStackResult {
  target: string
  url: string
  detected: TechStackDetectedTechnology[]
  summary: TechStackSummary
  grouped: Record<string, TechStackDetectedTechnology[]>
  technologies: string[]
  categorized: Record<string, string[]>
  categorized_verbose?: Record<string, string[]>
  metadata?: {
    final_url: string
    title: string
    status_code: number
    generated_at: string
  }
  cached?: boolean
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

export type UnifiedReconScanMode = 'quick' | 'standard' | 'deep'
export type UnifiedReconModuleState = 'pending' | 'running' | 'ok' | 'error'

export interface UnifiedReconModuleResult {
  ok: boolean
  duration_ms: number
  error: string | null
  data: Record<string, any>
  state?: UnifiedReconModuleState
}

export interface UnifiedReconJobStatus {
  job_id: string
  status: 'running' | 'completed' | 'failed'
  target: string
  scan_mode: UnifiedReconScanMode
  started_at: string
  updated_at: string
  module_order: string[]
  total_modules: number
  completed_modules: number
  modules: Record<string, UnifiedReconModuleResult>
  error?: string
  result?: UnifiedReconResult
}

export interface UnifiedReconFinding {
  module: string
  severity: 'Critical' | 'High' | 'Medium' | 'Low'
  title: string
  detail: string
  points: number
}

export interface UnifiedReconRiskDistribution {
  critical: number
  high: number
  medium: number
  low: number
}

export interface UnifiedReconModuleScore {
  risk_score: number
  weight: number
  grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F'
  risk_level: 'Excellent' | 'Good' | 'Moderate' | 'Risky' | 'Critical'
}

export interface UnifiedReconDNSSummary {
  dns_grade: string
  dnssec_enabled: boolean
  spf_status: 'Strong' | 'Weak' | 'Missing' | string
  dmarc_policy: 'Reject' | 'Quarantine' | 'None' | 'Missing' | string
  mx_count: number
  ns_count: number
  key_issues: string[]
  recommendations: string[]
}

export interface UnifiedReconSubdomainRow {
  host: string
  status: string
  risk: string
  title: string
}

export interface UnifiedReconSubdomainSummary {
  total_found: number
  live_hosts: number
  high_risk_hosts: number
  top_risky_subdomains: UnifiedReconSubdomainRow[]
  takeover_candidates: number
  public_dev_hosts: number
  key_issues: string[]
  recommendations: string[]
}

export interface UnifiedReconHeadersSummary {
  header_grade: string
  missing_security_headers: string[]
  cookie_security: string
  cookie_risk_count: number
  information_leakage: string[]
  hsts_status: string
  https_enforced: boolean
  key_issues: string[]
  recommendations: string[]
}

export interface UnifiedReconSSLSummary {
  valid: boolean
  status: string
  issuer: string
  expires_in_days: number
  cipher_strength: string
  key_issues: string[]
  recommendations: string[]
}

export interface UnifiedReconPortServiceRow {
  port: number
  service: string
  risk: 'Low' | 'Medium' | 'High' | string
  notes: string
}

export interface UnifiedReconPortsSummary {
  open_ports_count: number
  risky_ports_count: number
  services_table: UnifiedReconPortServiceRow[]
  key_issues: string[]
  recommendations: string[]
}

export interface UnifiedReconTechSummary {
  server: string[]
  frameworks: string[]
  cms: string[]
  cdn: string[]
  language: string[]
  all_technologies: string[]
}

export interface UnifiedReconWhoisSummary {
  registrar: string
  domain_age_days: number | null
  expiry_date: string
  registrant_country: string
  recommendations: string[]
}

export interface UnifiedReconModuleViews {
  dns?: UnifiedReconDNSSummary
  subdomains?: UnifiedReconSubdomainSummary
  headers?: UnifiedReconHeadersSummary
  ssl?: UnifiedReconSSLSummary
  ports?: UnifiedReconPortsSummary
  tech?: UnifiedReconTechSummary
  whois?: UnifiedReconWhoisSummary
}

export interface UnifiedReconHighlights {
  subdomains_found: number
  open_ports: number[]
  dns_grade: string
  header_grade: string
  ssl_status: string
  tech: string[]
}

export interface UnifiedReconResult {
  target: string
  normalized_domain: string | null
  scan_mode: UnifiedReconScanMode
  overall_score: number
  risk_score: number
  grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F'
  grade_label: string
  risk_level: 'Excellent' | 'Good' | 'Moderate' | 'Risky' | 'Critical'
  summary: string
  highlights: UnifiedReconHighlights
  issues: string[]
  findings: UnifiedReconFinding[]
  recommendations: string[]
  risk_distribution: UnifiedReconRiskDistribution
  module_scores: Record<string, UnifiedReconModuleScore>
  module_views: UnifiedReconModuleViews
  modules: Record<string, UnifiedReconModuleResult>
  scan_duration_ms: number
  cached: boolean
  generated_at: string
}
