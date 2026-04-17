import { createContext, ReactNode, useCallback, useContext, useMemo, useState } from 'react'
import { AlertTriangle, CheckCircle2, Info, X } from 'lucide-react'

type ToastVariant = 'success' | 'error' | 'info'

type ToastEntry = {
  id: number
  message: string
  variant: ToastVariant
}

type ToastContextValue = {
  pushToast: (message: string, variant?: ToastVariant) => void
}

const ToastContext = createContext<ToastContextValue | null>(null)

function variantStyles(variant: ToastVariant): string {
  if (variant === 'success') return 'border-green-500/30 bg-green-500/10 text-green-200'
  if (variant === 'error') return 'border-red-500/30 bg-red-500/10 text-red-200'
  return 'border-blue-500/30 bg-blue-500/10 text-blue-200'
}

function ToastIcon({ variant }: { variant: ToastVariant }) {
  if (variant === 'success') return <CheckCircle2 size={14} className="text-green-300" />
  if (variant === 'error') return <AlertTriangle size={14} className="text-red-300" />
  return <Info size={14} className="text-blue-300" />
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastEntry[]>([])

  const removeToast = useCallback((id: number) => {
    setToasts((current) => current.filter((entry) => entry.id !== id))
  }, [])

  const pushToast = useCallback((message: string, variant: ToastVariant = 'info') => {
    const id = Date.now() + Math.floor(Math.random() * 1000)
    setToasts((current) => [...current, { id, message, variant }].slice(-4))
    window.setTimeout(() => removeToast(id), 2800)
  }, [removeToast])

  const contextValue = useMemo<ToastContextValue>(() => ({ pushToast }), [pushToast])

  return (
    <ToastContext.Provider value={contextValue}>
      {children}
      <div className="fixed bottom-4 right-4 z-[90] flex flex-col gap-2 pointer-events-none w-[320px] max-w-[calc(100vw-1.5rem)]">
        {toasts.map((toast) => (
          <div
            key={toast.id}
            className={`pointer-events-auto rounded-lg border backdrop-blur-sm px-3 py-2 shadow-lg ${variantStyles(toast.variant)}`}
          >
            <div className="flex items-start gap-2">
              <ToastIcon variant={toast.variant} />
              <div className="text-xs font-mono leading-relaxed flex-1">{toast.message}</div>
              <button
                type="button"
                onClick={() => removeToast(toast.id)}
                className="text-gray-300 hover:text-white"
                aria-label="Dismiss notification"
              >
                <X size={12} />
              </button>
            </div>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  )
}

export function useToast() {
  const context = useContext(ToastContext)
  if (!context) {
    throw new Error('useToast must be used within ToastProvider')
  }
  return context
}
