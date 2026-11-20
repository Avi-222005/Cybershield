/**
 * Centralized API service for CyberShield Network Monitor.
 * Reuses the existing application's base URL and error handling patterns.
 */

import type {
  NetworkSummaryResponse,
  NetworkStatusResponse,
  NetworkInterfacesResponse,
  NetworkTrafficResponse,
  NetworkConnectionsResponse,
  NetworkProtocolsResponse,
  NetworkEventsResponse,
  NetworkHealthResponse,
  NetworkActionResponse,
  AlertsResponse,
  AlertDetailResponse,
  AlertsSummaryResponse,
  DetectionConfigResponse,
  AnalyticsResponse,
  AgentInfoResponse,
  AgentVersionResponse,
  AgentDeploymentResponse,
  AgentConfigResponse,
} from '../types/networkMonitor'

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || ''
const BASE = API_BASE_URL ? `${API_BASE_URL}/api/network` : '/api/network'

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
  })

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

  if (!res.ok) {
    throw new Error(data.error || `Request failed (${res.status})`)
  }

  return data as T
}

export const getNetworkSummary = () => request<NetworkSummaryResponse>('/summary')

export const getNetworkStatus = () => request<NetworkStatusResponse>('/status')

export const getNetworkInterfaces = () => request<NetworkInterfacesResponse>('/interfaces')

export const getNetworkTraffic = () => request<NetworkTrafficResponse>('/traffic')

export const getNetworkConnections = () => request<NetworkConnectionsResponse>('/connections')

export const getNetworkProtocols = () => request<NetworkProtocolsResponse>('/protocols')

export const getNetworkEvents = (limit: number = 50) =>
  request<NetworkEventsResponse>(`/events?limit=${encodeURIComponent(limit)}`)

export const getNetworkHealth = () => request<NetworkHealthResponse>('/health')

export const startMonitoring = (interfaceName?: string, forceAdapter?: string) =>
  request<NetworkActionResponse>('/start', {
    method: 'POST',
    body: JSON.stringify({ interface: interfaceName, force_adapter: forceAdapter }),
  })

export const stopMonitoring = () =>
  request<NetworkActionResponse>('/stop', {
    method: 'POST',
  })

// ==================== Module 5: Alerts API ====================

export interface AlertFilterParams {
  severity?: string
  status?: string
  category?: string
  search?: string
  limit?: number
}

export const getAlerts = (filters: AlertFilterParams = {}) => {
  const params = new URLSearchParams()
  if (filters.severity && filters.severity !== 'ALL') params.append('severity', filters.severity)
  if (filters.status && filters.status !== 'ALL') params.append('status', filters.status)
  if (filters.category && filters.category !== 'ALL') params.append('category', filters.category)
  if (filters.search) params.append('search', filters.search)
  if (filters.limit) params.append('limit', String(filters.limit))

  const qs = params.toString()
  return request<AlertsResponse>(`/alerts${qs ? `?${qs}` : ''}`)
}

export const getAlertDetails = (alertId: string) =>
  request<AlertDetailResponse>(`/alerts/${encodeURIComponent(alertId)}`)

export const acknowledgeAlert = (alertId: string) =>
  request<AlertDetailResponse>(`/alerts/${encodeURIComponent(alertId)}/acknowledge`, {
    method: 'POST',
  })

export const investigateAlert = (alertId: string, notes?: string) =>
  request<AlertDetailResponse>(`/alerts/${encodeURIComponent(alertId)}/investigate`, {
    method: 'POST',
    body: JSON.stringify({ notes }),
  })

export const resolveAlert = (alertId: string, notes?: string) =>
  request<AlertDetailResponse>(`/alerts/${encodeURIComponent(alertId)}/resolve`, {
    method: 'POST',
    body: JSON.stringify({ notes }),
  })

export const markAlertFalsePositive = (alertId: string, reason?: string) =>
  request<AlertDetailResponse>(`/alerts/${encodeURIComponent(alertId)}/false-positive`, {
    method: 'POST',
    body: JSON.stringify({ reason }),
  })

export const getAlertsSummary = () => request<AlertsSummaryResponse>('/alerts/summary')

// ==================== Module 4: Threat Detection Configuration ====================

export const getDetectionConfig = () => request<DetectionConfigResponse>('/detection/config')

export const updateDetectionConfig = (ruleId: string, config: Record<string, any>) =>
  request<DetectionConfigResponse>('/detection/config', {
    method: 'POST',
    body: JSON.stringify({ rule_id: ruleId, config }),
  })

// ==================== Module 6: Advanced Analytics ====================

export const getAnalytics = (limitIps: number = 15) =>
  request<AnalyticsResponse>(`/analytics?limit_ips=${encodeURIComponent(limitIps)}`)

// ==================== Module 7: Agent Management ====================

export const getAgentInfo = () => request<AgentInfoResponse>('/agent/info')

export const getAgentVersion = () => request<AgentVersionResponse>('/agent/version')

export const getAgentDeployment = () => request<AgentDeploymentResponse>('/agent/deployment')

export const getAgentConfig = () => request<AgentConfigResponse>('/agent/config')

export const updateAgentConfig = (configOverrides: Record<string, any>) =>
  request<AgentConfigResponse>('/agent/config', {
    method: 'POST',
    body: JSON.stringify(configOverrides),
  })
