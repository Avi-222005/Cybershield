import React, { useEffect, useState } from 'react'
import type { DetectionRuleConfig } from '../../../types/networkMonitor'
import { getDetectionConfig, updateDetectionConfig } from '../../../services/networkMonitorService'
import { AlertSeverityBadge } from './AlertSeverityBadge'
import { ShieldAlert, Settings as SettingsIcon, Save, CheckCircle2, RotateCcw } from 'lucide-react'
import { cn } from '../../../lib/utils'

export function DetectionRuleSettings() {
  const [rules, setRules] = useState<DetectionRuleConfig[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [savingRuleId, setSavingRuleId] = useState<string | null>(null)
  const [statusMessage, setStatusMessage] = useState<string | null>(null)
  const [editedConfigs, setEditedConfigs] = useState<Record<string, Record<string, any>>>({})

  const fetchRules = async () => {
    setIsLoading(true)
    try {
      const res = await getDetectionConfig()
      if (res.success) {
        setRules(res.rules)
        const initialMap: Record<string, Record<string, any>> = {}
        res.rules.forEach((r) => {
          initialMap[r.rule_id] = { ...r.config, enabled: r.enabled }
        })
        setEditedConfigs(initialMap)
      }
    } catch (err: any) {
      console.warn('Failed to load detection rules:', err?.message)
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    fetchRules()
  }, [])

  const handleToggle = (ruleId: string, currentEnabled: boolean) => {
    setEditedConfigs((prev) => ({
      ...prev,
      [ruleId]: {
        ...prev[ruleId],
        enabled: !currentEnabled,
      },
    }))
  }

  const handleParamChange = (ruleId: string, paramKey: string, value: any) => {
    setEditedConfigs((prev) => ({
      ...prev,
      [ruleId]: {
        ...prev[ruleId],
        [paramKey]: value,
      },
    }))
  }

  const handleSaveRule = async (ruleId: string) => {
    const cfg = editedConfigs[ruleId]
    if (!cfg) return

    setSavingRuleId(ruleId)
    setStatusMessage(null)
    try {
      const res = await updateDetectionConfig(ruleId, cfg)
      if (res.success) {
        setStatusMessage(`Rule '${ruleId}' configuration updated successfully.`)
        await fetchRules()
        setTimeout(() => setStatusMessage(null), 3500)
      }
    } catch (err: any) {
      setStatusMessage(`Error saving rule: ${err?.message}`)
    } finally {
      setSavingRuleId(null)
    }
  }

  if (isLoading) {
    return (
      <div className="glass-card rounded-2xl border border-cyber-border p-6 text-center text-xs font-mono text-gray-400">
        Loading detection rules...
      </div>
    )
  }

  return (
    <div className="glass-card rounded-2xl border border-cyber-border p-6 shadow-xl space-y-5">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-cyber-border/40 pb-4">
        <div>
          <h3 className="text-base font-bold text-gray-900 dark:text-white flex items-center gap-2">
            <ShieldAlert size={18} className="text-[#0d6efd]" />
            Threat Detection Rules Configuration
          </h3>
          <p className="text-xs text-gray-400 mt-0.5">
            5 modular heuristic and statistical detection rules. Fully in-memory, defensive inspection.
          </p>
        </div>
        {statusMessage && (
          <div className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-xs font-mono">
            <CheckCircle2 size={13} />
            <span>{statusMessage}</span>
          </div>
        )}
      </div>

      <div className="space-y-4">
        {rules.map((rule) => {
          const edited = editedConfigs[rule.rule_id] || {}
          const isEnabled = edited.enabled !== undefined ? edited.enabled : rule.enabled
          const isSaving = savingRuleId === rule.rule_id

          return (
            <div
              key={rule.rule_id}
              className={cn(
                'rounded-xl border p-4 transition-all duration-200',
                isEnabled
                  ? 'bg-cyber-surface/40 border-cyber-border/70'
                  : 'bg-cyber-surface/10 border-cyber-border/30 opacity-70'
              )}
            >
              {/* Header */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-2">
                <div className="flex items-center gap-2.5 flex-wrap">
                  <span className="font-bold text-sm text-gray-100">{rule.name}</span>
                  <AlertSeverityBadge severity={rule.severity} />
                  <span className="text-[10px] font-mono text-gray-500 bg-cyber-surface/60 px-2 py-0.5 rounded border border-cyber-border/40">
                    {rule.category}
                  </span>
                </div>

                <div className="flex items-center gap-3">
                  {/* Toggle Button */}
                  <label className="flex items-center gap-2 cursor-pointer text-xs font-mono">
                    <span className="text-gray-400">{isEnabled ? 'Active' : 'Disabled'}</span>
                    <input
                      type="checkbox"
                      checked={isEnabled}
                      onChange={() => handleToggle(rule.rule_id, isEnabled)}
                      className="sr-only peer"
                    />
                    <div className="w-9 h-5 bg-cyber-surface peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-[#0d6efd] border border-cyber-border relative" />
                  </label>

                  <button
                    type="button"
                    onClick={() => handleSaveRule(rule.rule_id)}
                    disabled={isSaving}
                    className="inline-flex items-center gap-1.5 px-3 py-1 rounded-lg bg-[#0d6efd]/15 hover:bg-[#0d6efd]/25 border border-[#0d6efd]/30 text-[#0d6efd] text-xs font-mono font-medium transition-colors disabled:opacity-50"
                  >
                    <Save size={12} />
                    <span>{isSaving ? 'Saving...' : 'Save'}</span>
                  </button>
                </div>
              </div>

              {/* Description */}
              <p className="text-xs text-gray-400 mb-3">{rule.description}</p>

              {/* Parameters Grid */}
              {rule.config && Object.keys(rule.config).length > 0 && (
                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 pt-2 border-t border-cyber-border/30">
                  {Object.entries(rule.config).map(([paramKey, val]) => {
                    const currentVal = edited[paramKey] !== undefined ? edited[paramKey] : val
                    const isNum = typeof val === 'number'

                    return (
                      <div key={paramKey} className="text-xs font-mono">
                        <label className="text-gray-500 block mb-1 text-[11px] capitalize">
                          {paramKey.replace(/_/g, ' ')}
                        </label>
                        <input
                          type={isNum ? 'number' : 'text'}
                          value={currentVal}
                          onChange={(e) =>
                            handleParamChange(
                              rule.rule_id,
                              paramKey,
                              isNum ? parseFloat(e.target.value) || 0 : e.target.value
                            )
                          }
                          className="w-full px-2.5 py-1 rounded-lg bg-cyber-bg border border-cyber-border/60 text-xs text-white font-mono focus:outline-none focus:border-[#0d6efd]"
                        />
                      </div>
                    )
                  })}
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
