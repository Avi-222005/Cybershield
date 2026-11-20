import React, { useEffect, useState } from 'react'
import { useOutletContext } from 'react-router-dom'
import type { NetworkMonitorContextType } from './NetworkMonitorLayout'
import type { AgentInfo, AgentDeployment } from '../../types/networkMonitor'
import {
  getAgentInfo,
  getAgentDeployment,
  getAgentConfig,
  updateAgentConfig,
} from '../../services/networkMonitorService'
import InterfaceSelector from '../../components/network-monitor/InterfaceSelector'
import AgentStatus from '../../components/network-monitor/AgentStatus'
import { DetectionRuleSettings } from '../../components/network-monitor/alerts/DetectionRuleSettings'
import {
  Settings as SettingsIcon,
  Wifi,
  ShieldCheck,
  Cpu,
  Lock,
  Play,
  Square,
  RefreshCw,
  Clock,
  Activity,
  Layers,
  CheckCircle2,
  AlertTriangle,
  Server,
  Monitor,
  Terminal,
  Database,
  FileCode,
} from 'lucide-react'
import { cn } from '../../lib/utils'

export default function Settings() {
  const {
    summary,
    interfaces,
    start,
    stop,
    reloadInterfaces,
    isStarting,
    isStopping,
  } = useOutletContext<NetworkMonitorContextType>()

  const agentState = summary?.status.state || 'STOPPED'
  const isRunning = agentState === 'RUNNING'
  const currentInterface = summary?.selected_interface || null
  const components = summary?.status.components || {}
  const uptime = summary?.status.uptime_seconds || 0
  const readiness = summary?.readiness

  const [agentInfo, setAgentInfo] = useState<AgentInfo | null>(null)
  const [deployment, setDeployment] = useState<AgentDeployment | null>(null)
  const [agentConfig, setAgentConfig] = useState<Record<string, any> | null>(null)

  const fetchAgentDetails = async () => {
    try {
      const [infoRes, depRes, cfgRes] = await Promise.all([
        getAgentInfo(),
        getAgentDeployment(),
        getAgentConfig(),
      ])
      if (infoRes.success) setAgentInfo(infoRes.info)
      if (depRes.success) setDeployment(depRes.deployment)
      if (cfgRes.success) setAgentConfig(cfgRes.config)
    } catch (err: any) {
      console.warn('Failed to load agent management details:', err?.message)
    }
  }

  useEffect(() => {
    fetchAgentDetails()
  }, [agentState])

  const handleSelectInterface = async (name: string) => {
    if (isRunning) {
      await stop()
      await start(name)
    } else {
      await start(name)
    }
    await reloadInterfaces()
    await fetchAgentDetails()
  }

  const formatUptime = (seconds: number) => {
    const mins = Math.floor(seconds / 60)
    const secs = Math.floor(seconds % 60)
    const hrs = Math.floor(mins / 60)
    if (hrs > 0) return `${hrs}h ${mins % 60}m ${secs}s`
    if (mins > 0) return `${mins}m ${secs}s`
    return `${secs}s`
  }

  return (
    <div className="space-y-6">
      {/* Network Interface Selection Section */}
      <div className="glass-card rounded-2xl border border-cyber-border p-6 shadow-xl">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-5 border-b border-cyber-border/40 pb-4">
          <div>
            <h3 className="text-lg font-bold text-gray-900 dark:text-white flex items-center gap-2">
              <Wifi size={20} className="text-[#0d6efd]" />
              Network Interface Selection
            </h3>
            <p className="text-xs text-gray-400 mt-0.5">
              Select the network adapter to monitor on this Windows machine
            </p>
          </div>
          <button
            onClick={() => reloadInterfaces()}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-cyber-surface/70 hover:bg-cyber-surface border border-cyber-border/60 text-xs font-mono text-gray-300 transition-colors"
          >
            <RefreshCw size={13} />
            <span>Scan Adapters</span>
          </button>
        </div>

        <InterfaceSelector
          interfaces={interfaces}
          selectedInterface={currentInterface}
          agentState={agentState}
          onSelect={handleSelectInterface}
        />
      </div>

      {/* Deployment Mode Status Card (Local vs Server) */}
      <div className="glass-card rounded-2xl border border-cyber-border p-6 shadow-xl">
        <div className="border-b border-cyber-border/40 pb-4 mb-4">
          <h3 className="text-base font-bold text-gray-900 dark:text-white flex items-center gap-2">
            <Server size={18} className="text-[#0d6efd]" />
            Deployment Architecture & Targets
          </h3>
          <p className="text-xs text-gray-400 mt-0.5">
            CyberShield Network Monitor supports both local endpoint monitoring and scheduled server agents
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono text-xs">
          {/* Local Host Agent */}
          <div className="p-4 rounded-xl bg-cyber-surface/50 border border-cyber-border/70 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <Monitor size={16} className="text-emerald-400" />
                  <span className="font-bold text-gray-100 text-sm">Local Windows Agent</span>
                </div>
                <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                  {deployment?.local.status.toUpperCase() || 'OPERATIONAL'}
                </span>
              </div>
              <p className="text-gray-400 text-[11px] mb-3 leading-relaxed">
                Native Windows 10/11 process capturing authorized interface traffic metadata and socket connections directly on this machine.
              </p>
            </div>
            <div className="pt-2 border-t border-cyber-border/30 flex items-center justify-between text-[11px] text-gray-400">
              <span>Adapter: {currentInterface || 'Auto'}</span>
              <span className={isRunning ? 'text-emerald-400' : 'text-gray-500'}>
                {isRunning ? '● Active' : '○ Standby'}
              </span>
            </div>
          </div>

          {/* Remote Server Agent */}
          <div className="p-4 rounded-xl bg-cyber-surface/30 border border-cyber-border/40 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <Server size={16} className="text-blue-400" />
                  <span className="font-bold text-gray-300 text-sm">Linux / Server Agent</span>
                </div>
                <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-blue-500/10 text-blue-400 border border-blue-500/30">
                  {deployment?.server.status.toUpperCase() || 'PLANNED'}
                </span>
              </div>
              <p className="text-gray-400 text-[11px] mb-3 leading-relaxed">
                Headless Linux and cloud server telemetry agent for centralized fleet monitoring across perimeter servers and Kubernetes nodes.
              </p>
            </div>
            <div className="pt-2 border-t border-cyber-border/30 flex items-center justify-between text-[11px] text-gray-500">
              <span>Integration: Multi-agent roadmap</span>
              <span>Planned</span>
            </div>
          </div>
        </div>
      </div>

      {/* Agent Diagnostics & Privacy Invariants */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Agent Metadata & Buffer Stats */}
        <div className="glass-card rounded-2xl border border-cyber-border p-6 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3 border-b border-cyber-border/40 pb-3">
              <h3 className="text-base font-bold text-gray-900 dark:text-white flex items-center gap-2">
                <Terminal size={18} className="text-[#0d6efd]" />
                Agent Information & Diagnostics
              </h3>
              <span className="px-2.5 py-0.5 rounded-md bg-[#0d6efd]/15 text-[#0d6efd] font-mono text-xs border border-[#0d6efd]/30 font-bold">
                v{agentInfo?.version || '1.1.0'}
              </span>
            </div>

            <div className="space-y-2.5 font-mono text-xs">
              <div className="flex items-center justify-between p-2 rounded-lg bg-cyber-surface/40 border border-cyber-border/30">
                <span className="text-gray-400">Agent Name</span>
                <span className="text-gray-200">{agentInfo?.agent_name || 'CyberShield Network Agent'}</span>
              </div>
              <div className="flex items-center justify-between p-2 rounded-lg bg-cyber-surface/40 border border-cyber-border/30">
                <span className="text-gray-400">Python Runtime</span>
                <span className="text-gray-200">{agentInfo?.python_version || 'Python 3.11+'}</span>
              </div>
              <div className="flex items-center justify-between p-2 rounded-lg bg-cyber-surface/40 border border-cyber-border/30">
                <span className="text-gray-400">Operating System</span>
                <span className="text-gray-200">Windows (Win32)</span>
              </div>
              <div className="flex items-center justify-between p-2 rounded-lg bg-cyber-surface/40 border border-cyber-border/30">
                <span className="text-gray-400">Packet Ring Buffer</span>
                <span className="text-gray-200">
                  {summary?.status.memory_buffer_usage.packet_events || 0} /{' '}
                  {summary?.status.memory_buffer_usage.max_packet_events || 5000} items
                </span>
              </div>
              <div className="flex items-center justify-between p-2 rounded-lg bg-cyber-surface/40 border border-cyber-border/30">
                <span className="text-gray-400">Alert Ring Buffer</span>
                <span className="text-gray-200">
                  {summary?.status.memory_buffer_usage.alerts || 0} / 500 items
                </span>
              </div>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-cyber-border/40 flex items-center justify-between text-xs font-mono">
            <span className="text-gray-400">Session Uptime:</span>
            <span className="text-gray-200 font-bold">{formatUptime(uptime)}</span>
          </div>
        </div>

        {/* Strict Privacy & Invariant Guarantees */}
        <div className="glass-card rounded-2xl border border-cyber-border p-6 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3 border-b border-cyber-border/40 pb-3">
              <h3 className="text-base font-bold text-gray-900 dark:text-white flex items-center gap-2">
                <Lock size={18} className="text-cyan-400" />
                Immutable Privacy Invariants
              </h3>
              <span className="text-[11px] font-mono text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20 font-bold">
                ENFORCED
              </span>
            </div>

            <div className="space-y-2.5 font-mono text-xs">
              <div className="p-2.5 rounded-lg bg-cyber-surface/40 border border-cyber-border/30 flex items-start gap-2.5">
                <CheckCircle2 size={15} className="text-emerald-400 mt-0.5 flex-shrink-0" />
                <div>
                  <span className="font-bold text-gray-200">store_payloads = False</span>
                  <p className="text-[11px] text-gray-400 mt-0.5">
                    Payload extraction is disabled at the capture driver and parser level. Cannot be overridden.
                  </p>
                </div>
              </div>

              <div className="p-2.5 rounded-lg bg-cyber-surface/40 border border-cyber-border/30 flex items-start gap-2.5">
                <CheckCircle2 size={15} className="text-emerald-400 mt-0.5 flex-shrink-0" />
                <div>
                  <span className="font-bold text-gray-200">persist_traffic = False</span>
                  <p className="text-[11px] text-gray-400 mt-0.5">
                    No PCAP capture files, SQLite tables, or disk logs are created. Telemetry exists strictly in RAM.
                  </p>
                </div>
              </div>

              <div className="p-2.5 rounded-lg bg-cyber-surface/40 border border-cyber-border/30 flex items-start gap-2.5">
                <CheckCircle2 size={15} className="text-emerald-400 mt-0.5 flex-shrink-0" />
                <div>
                  <span className="font-bold text-gray-200">Immediate Purge on Stop</span>
                  <p className="text-[11px] text-gray-400 mt-0.5">
                    Stopping the monitoring agent instantly flushes all rolling buffers, packet queues, and alert maps.
                  </p>
                </div>
              </div>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-cyber-border/40 flex items-center justify-between text-[11px] font-mono text-gray-500">
            <span>Storage Policy: IN_MEMORY_SESSION_ONLY</span>
            <span>Zero Payload Retention</span>
          </div>
        </div>
      </div>

      {/* Threat Detection Rules Configuration (Module 4) */}
      <DetectionRuleSettings />
    </div>
  )
}
