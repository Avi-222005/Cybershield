import { CheckCircle2, Loader2, XCircle } from 'lucide-react'
import type { UnifiedReconModuleResult } from '../../../types'

type Props = {
  moduleOrder: string[]
  moduleLabels: Record<string, string>
  modules: Record<string, UnifiedReconModuleResult>
  loading: boolean
  progressStep: number
}

function moduleState(
  moduleOrder: string[],
  moduleKey: string,
  loading: boolean,
  progressStep: number,
  modules: Record<string, UnifiedReconModuleResult>,
): 'pending' | 'running' | 'ok' | 'error' {
  const index = moduleOrder.indexOf(moduleKey)

  if (loading) {
    if (index < progressStep) return 'ok'
    if (index === progressStep) return 'running'
    return 'pending'
  }

  const result = modules[moduleKey]
  if (!result) return 'pending'
  return result.ok ? 'ok' : 'error'
}

export default function CompactModuleStatusGrid({
  moduleOrder,
  moduleLabels,
  modules,
  loading,
  progressStep,
}: Props) {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-2.5">
      {moduleOrder.map((moduleKey) => {
        const status = moduleState(moduleOrder, moduleKey, loading, progressStep, modules)
        const moduleInfo = modules[moduleKey]

        return (
          <div
            key={moduleKey}
            className="rounded-lg border border-white/10 bg-white/3 px-3 py-2.5"
          >
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center gap-2 min-w-0">
                {status === 'ok' ? (
                  <CheckCircle2 size={14} className="text-green-400 shrink-0" />
                ) : status === 'error' ? (
                  <XCircle size={14} className="text-red-400 shrink-0" />
                ) : status === 'running' ? (
                  <Loader2 size={14} className="text-[#6ea8fe] shrink-0 animate-spin" />
                ) : (
                  <div className="h-2.5 w-2.5 rounded-full bg-gray-500 shrink-0" />
                )}

                <span className="text-xs sm:text-sm text-gray-200 font-mono truncate">
                  {moduleLabels[moduleKey] || moduleKey}
                </span>
              </div>

              <span
                className={`text-[10px] sm:text-xs px-2 py-0.5 rounded border font-mono whitespace-nowrap ${
                  status === 'ok'
                    ? 'text-green-300 border-green-500/30 bg-green-500/10'
                    : status === 'error'
                    ? 'text-red-300 border-red-500/30 bg-red-500/10'
                    : status === 'running'
                    ? 'text-[#6ea8fe] border-[#0d6efd]/30 bg-[#0d6efd]/10'
                    : 'text-gray-400 border-white/10 bg-white/5'
                }`}
              >
                {status.toUpperCase()}
              </span>
            </div>

            <div className="mt-1 text-[10px] text-gray-500 font-mono">
              {moduleInfo ? `${moduleInfo.duration_ms} ms` : 'Pending'}
            </div>

            {loading && (
              <div className="mt-2 h-1.5 rounded-full bg-white/10 overflow-hidden">
                <div
                  className={`h-full transition-all duration-300 ${
                    status === 'ok'
                      ? 'bg-green-500/70 w-full'
                      : status === 'running'
                      ? 'bg-[#0d6efd]/80 w-2/3 animate-pulse'
                      : status === 'error'
                      ? 'bg-red-500/70 w-1/2'
                      : 'bg-white/20 w-1/4'
                  }`}
                />
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}
