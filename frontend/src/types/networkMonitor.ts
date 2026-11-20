/**
 * TypeScript definitions for CyberShield Network Monitor.
 */

export type AgentState =
  | 'STOPPED'
  | 'INITIALIZING'
  | 'RUNNING'
  | 'STOPPING'
  | 'ERROR'
  | 'DEGRADED'

export type ComponentStatus =
  | 'HEALTHY'
  | 'DEGRADED'
  | 'ERROR'
  | 'STOPPED'
  | 'DISABLED'

export interface ComponentHealth {
  name: string
  status: ComponentStatus
  details?: string
  last_updated?: number
  error_count?: number
}

export interface NetworkInterface {
  name: string
  is_up: boolean
  speed: number
  mtu: number
  ipv4: string[]
  ipv6: string[]
  mac_address: string | null
  selected: boolean
  is_default?: boolean
}

export interface BandwidthStats {
  interface: string
  upload_bytes_per_sec: number
  download_bytes_per_sec: number
  upload_mbps: number
  download_mbps: number
  total_bytes_sent: number
  total_bytes_received: number
  packets_sent?: number
  packets_received?: number
  packets_sent_per_sec: number
  packets_recv_per_sec: number
  captured_packets_per_sec?: number
  timestamp: number
  active?: boolean
}

export interface PacketCaptureStats {
  interface: string
  total_packets_captured: number
  packets_per_sec: number
  dropped_packets: number
  protocol_distribution: Record<string, number>
  direction_distribution: {
    inbound: number
    outbound: number
    internal: number
    unknown: number
  }
  timestamp: number
}

export interface NetworkConnection {
  local_ip: string
  local_port: number
  remote_ip: string
  remote_port: number
  protocol: string
  status: string
  pid: number | null
  process_name: string | null
}

export interface PacketEvent {
  timestamp: number
  interface: string
  source_ip: string | null
  destination_ip: string | null
  source_port: number | null
  destination_port: number | null
  protocol: string
  packet_size: number
  direction: 'inbound' | 'outbound' | 'internal' | 'unknown' | string
}

export interface MemoryBufferUsage {
  packet_events: number
  max_packet_events: number
  connections: number
  alerts: number
}

export interface NetworkStatus {
  state: AgentState
  uptime_seconds: number
  monitored_interface: string | null
  active_connections_count: number
  memory_buffer_usage: MemoryBufferUsage
  components: Record<string, ComponentHealth>
}

export interface SystemReadiness {
  full_live_capture_ready: boolean
  basic_monitoring_ready: boolean
  python: { passed: boolean; version: string; message: string }
  tshark: { passed: boolean; path: string | null; message: string }
  npcap: { passed: boolean; npcap_detected: boolean; message: string }
  admin: { passed: boolean; is_admin: boolean; message: string }
}

export interface NetworkSummary {
  status: NetworkStatus
  traffic: BandwidthStats
  protocols: PacketCaptureStats
  active_connections_count: number
  recent_events: PacketEvent[]
  selected_interface: string | null
  readiness?: SystemReadiness
}

export interface NetworkSummaryResponse {
  success: boolean
  summary: NetworkSummary
  error?: string
}

export interface NetworkStatusResponse {
  success: boolean
  status: NetworkStatus
  error?: string
}

export interface NetworkInterfacesResponse {
  success: boolean
  interfaces: NetworkInterface[]
  count: number
  error?: string
}

export interface NetworkTrafficResponse {
  success: boolean
  traffic: BandwidthStats
  error?: string
}

export interface NetworkConnectionsResponse {
  success: boolean
  connections: NetworkConnection[]
  count: number
  error?: string
}

export interface NetworkProtocolsResponse {
  success: boolean
  protocols: PacketCaptureStats
  error?: string
}

export interface NetworkEventsResponse {
  success: boolean
  events: PacketEvent[]
  count: number
  error?: string
}

export interface NetworkHealthResponse {
  success: boolean
  health: {
    backend_online: boolean
    agent_state: AgentState
    readiness: SystemReadiness
    components: Record<string, ComponentHealth>
  }
  error?: string
}

export interface NetworkActionResponse {
  success: boolean
  message?: string
  state?: AgentState
  interface?: string
  error?: string
}

export interface TrafficDataPoint {
  time: string
  timestamp: number
  downloadMbps: number
  uploadMbps: number
  downloadKBps: number
  uploadKBps: number
}

// ==================== Module 4 & 5: Security Alerts & Threat Detection Types ====================

export type AlertSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'

export type AlertStatus =
  | 'NEW'
  | 'ACKNOWLEDGED'
  | 'INVESTIGATING'
  | 'RESOLVED'
  | 'FALSE_POSITIVE'

export interface SecurityAlert {
  alert_id: string
  rule_id: string
  title: string
  category: string
  severity: AlertSeverity
  confidence: number
  description: string
  reason: string
  source_ip: string | null
  destination_ip: string | null
  destination_ports: number[]
  protocol: string | null
  process_name: string | null
  first_seen: number
  last_seen: number
  timestamp: number
  occurrence_count: number
  status: AlertStatus
  evidence: Record<string, any>
  notes?: string
  false_positive_reason?: string
  fingerprint?: string
}

export interface AlertsSummary {
  total: number
  critical: number
  high: number
  medium: number
  low: number
  new: number
  acknowledged: number
  investigating: number
  resolved: number
  false_positive: number
}

export interface DetectionRuleConfig {
  rule_id: string
  name: string
  category: string
  severity: AlertSeverity
  description: string
  enabled: boolean
  config: Record<string, any>
}

// ==================== Module 6: Advanced Analytics Types ====================

export interface HourlyTrafficBucket {
  bucket_id: number
  label: string
  upload_bytes: number
  download_bytes: number
  packets: number
  start_time: number
}

export interface TopCommunicatingIP {
  ip: string
  packets: number
  bytes: number
  inbound_count: number
  outbound_count: number
  first_seen: number
  last_seen: number
}

export interface ProcessAttribution {
  process_name: string
  pid: number | null
  socket_count: number
  protocols: string[]
  remote_endpoints_sample: string[]
  attribution_type: string
}

export interface AnalyticsData {
  session: {
    start_time: number
    uptime_seconds: number
    storage_policy: string
    data_cleared_on_stop: boolean
  }
  bandwidth: {
    total_bytes_sent: number
    total_bytes_received: number
    total_bytes_combined: number
    peak_upload_mbps: number
    peak_download_mbps: number
    average_upload_mbps: number
    average_download_mbps: number
    samples_count: number
    has_sufficient_samples: boolean
  }
  packets: {
    total_captured: number
    average_packets_per_sec: number
    current_packets_per_sec: number
    dropped_packets: number
  }
  top_ips: TopCommunicatingIP[]
  total_tracked_ips_count: number
  processes: ProcessAttribution[]
  protocols: Record<string, number>
  directions: Record<string, number>
  hourly_traffic: HourlyTrafficBucket[]
}

// ==================== Module 7: Agent Management Types ====================

export interface AgentInfo {
  agent_name: string
  version: string
  platform: string
  python_version: string
  state: AgentState
  monitored_interface: string | null
  uptime_seconds: number
  memory_buffers: MemoryBufferUsage
  components: Record<string, ComponentHealth>
  readiness: SystemReadiness
  privacy_policy: {
    store_payloads: boolean
    persist_traffic: boolean
    retention_mode: string
    description: string
  }
  threat_detection_rules_count: number
}

export interface AgentDeployment {
  local: {
    status: string
    platform: string
    description: string
    interface: string | null
    is_active: boolean
  }
  server: {
    status: string
    platform: string
    description: string
    is_active: boolean
  }
}

// ==================== API Response Wrappers ====================

export interface AlertsResponse {
  success: boolean
  alerts: SecurityAlert[]
  count: number
  error?: string
}

export interface AlertDetailResponse {
  success: boolean
  alert: SecurityAlert
  error?: string
}

export interface AlertsSummaryResponse {
  success: boolean
  summary: AlertsSummary
  error?: string
}

export interface DetectionConfigResponse {
  success: boolean
  rules: DetectionRuleConfig[]
  count: number
  error?: string
}

export interface AnalyticsResponse {
  success: boolean
  analytics: AnalyticsData
  error?: string
}

export interface AgentInfoResponse {
  success: boolean
  info: AgentInfo
  error?: string
}

export interface AgentVersionResponse {
  success: boolean
  version: {
    version: string
    name: string
    build_date: string
    compatible_platforms: string[]
  }
  error?: string
}

export interface AgentDeploymentResponse {
  success: boolean
  deployment: AgentDeployment
  error?: string
}

export interface AgentConfigResponse {
  success: boolean
  config: Record<string, any>
  message?: string
  error?: string
}
