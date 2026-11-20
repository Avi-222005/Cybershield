import React, { useState } from 'react'
import type { NetworkInterface, AgentState } from '../../types/networkMonitor'
import { Wifi, Network, Check, AlertTriangle, Shield, X, Globe, Radio } from 'lucide-react'
import { cn } from '../../lib/utils'

interface InterfaceSelectorProps {
  interfaces: NetworkInterface[]
  selectedInterface: string | null
  agentState: AgentState
  onSelect: (interfaceName: string) => Promise<void> | void
  className?: string
}

export function InterfaceSelector({
  interfaces,
  selectedInterface,
  agentState,
  onSelect,
  className,
}: InterfaceSelectorProps) {
  const [pendingInterface, setPendingInterface] = useState<string | null>(null)
  const [showConfirmModal, setShowConfirmModal] = useState(false)
  const [isChanging, setIsChanging] = useState(false)

  const isRunning = agentState === 'RUNNING'

  const handleInterfaceClick = (name: string) => {
    if (name === selectedInterface) return

    if (isRunning) {
      // Must confirm before switching active running capture
      setPendingInterface(name)
      setShowConfirmModal(true)
    } else {
      onSelect(name)
    }
  }

  const handleConfirmSwitch = async () => {
    if (!pendingInterface) return
    setIsChanging(true)
    try {
      await onSelect(pendingInterface)
    } finally {
      setIsChanging(false)
      setShowConfirmModal(false)
      setPendingInterface(null)
    }
  }

  return (
    <div className={cn('space-y-3', className)}>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {interfaces.map((iface) => {
          const isSelected = iface.name === selectedInterface
          const isWifi = iface.name.toLowerCase().includes('wi-fi') || iface.name.toLowerCase().includes('wireless')
          const Icon = isWifi ? Wifi : Network

          return (
            <div
              key={iface.name}
              onClick={() => handleInterfaceClick(iface.name)}
              className={cn(
                'glass-card rounded-xl p-4 border transition-all cursor-pointer flex flex-col justify-between relative overflow-hidden',
                isSelected
                  ? 'border-[#0d6efd] bg-[#0d6efd]/5 shadow-[0_0_15px_rgba(13,110,253,0.1)]'
                  : 'border-cyber-border hover:border-gray-500/50'
              )}
            >
              <div className="flex items-start justify-between mb-2">
                <div className="flex items-center gap-2.5">
                  <div
                    className={cn(
                      'p-2 rounded-lg border',
                      isSelected
                        ? 'bg-[#0d6efd]/10 border-[#0d6efd]/40 text-[#0d6efd]'
                        : 'bg-cyber-surface/60 border-cyber-border text-gray-400'
                    )}
                  >
                    <Icon size={18} />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <h4 className="text-sm font-bold text-gray-900 dark:text-white font-mono">
                        {iface.name}
                      </h4>
                      {iface.is_default && (
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                          DEFAULT
                        </span>
                      )}
                    </div>
                    <span className="text-[11px] text-gray-400 font-mono">
                      MAC: {iface.mac_address || 'N/A'}
                    </span>
                  </div>
                </div>

                <div className="flex items-center gap-1.5">
                  <span
                    className={cn(
                      'px-2 py-0.5 rounded-full text-[10px] font-mono font-bold border',
                      iface.is_up
                        ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                        : 'bg-gray-500/10 text-gray-400 border-gray-500/30'
                    )}
                  >
                    {iface.is_up ? 'UP' : 'DOWN'}
                  </span>
                  {isSelected && (
                    <span className="w-5 h-5 rounded-full bg-[#0d6efd] text-white flex items-center justify-center">
                      <Check size={12} strokeWidth={3} />
                    </span>
                  )}
                </div>
              </div>

              {/* IP addresses list */}
              <div className="mt-2 pt-2 border-t border-cyber-border/30 text-xs font-mono space-y-1">
                <div className="flex items-center justify-between text-gray-400">
                  <span>IPv4:</span>
                  <span className="text-gray-200 font-medium">
                    {iface.ipv4.length > 0 ? iface.ipv4.join(', ') : 'None assigned'}
                  </span>
                </div>
                {iface.ipv6.length > 0 && (
                  <div className="flex items-center justify-between text-gray-400 text-[11px]">
                    <span>IPv6:</span>
                    <span className="text-gray-400 truncate max-w-[200px]" title={iface.ipv6[0]}>
                      {iface.ipv6[0]}
                    </span>
                  </div>
                )}
              </div>
            </div>
          )
        })}
      </div>

      {/* Confirmation Modal when switching during live monitoring */}
      {showConfirmModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm animate-in fade-in duration-150">
          <div className="glass-card rounded-2xl border border-cyber-border max-w-md w-full p-6 shadow-2xl relative">
            <button
              onClick={() => setShowConfirmModal(false)}
              className="absolute top-4 right-4 p-1.5 rounded-lg text-gray-400 hover:text-white hover:bg-white/5"
            >
              <X size={18} />
            </button>

            <div className="flex items-center gap-3 mb-4 text-amber-400">
              <div className="w-10 h-10 rounded-xl bg-amber-500/10 border border-amber-500/30 flex items-center justify-center">
                <AlertTriangle size={20} />
              </div>
              <div>
                <h3 className="text-base font-bold text-gray-900 dark:text-white font-mono">
                  Change Monitored Interface?
                </h3>
                <span className="text-xs text-gray-400">Active capture session in progress</span>
              </div>
            </div>

            <p className="text-sm text-gray-300 leading-relaxed mb-5 font-mono text-xs">
              Monitoring is currently active on <strong className="text-white">'{selectedInterface}'</strong>.
              Switching to <strong className="text-[#0d6efd]">'{pendingInterface}'</strong> will restart
              the monitoring engine and rebind packet capture.
            </p>

            <div className="flex items-center justify-end gap-2.5">
              <button
                onClick={() => setShowConfirmModal(false)}
                disabled={isChanging}
                className="px-4 py-2 rounded-xl bg-cyber-surface hover:bg-cyber-surface/80 border border-cyber-border text-xs font-semibold text-gray-300"
              >
                Cancel
              </button>
              <button
                onClick={handleConfirmSwitch}
                disabled={isChanging}
                className="px-4 py-2 rounded-xl bg-[#0d6efd] hover:bg-[#0b5ed7] text-white text-xs font-semibold transition-all shadow-[0_0_12px_rgba(13,110,253,0.3)] disabled:opacity-50"
              >
                {isChanging ? 'Switching...' : 'Switch Interface'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
export default InterfaceSelector
