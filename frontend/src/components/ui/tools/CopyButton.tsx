import { Check, Copy } from 'lucide-react'
import { useState } from 'react'
import { cn } from '../../../lib/utils'
import { useToast } from '../../../context/ToastContext'

type CopyButtonProps = {
  value: string
  label?: string
  className?: string
  disabled?: boolean
  successMessage?: string
}

export default function CopyButton({
  value,
  label = 'Copy',
  className,
  disabled,
  successMessage = 'Copied to clipboard',
}: CopyButtonProps) {
  const [copied, setCopied] = useState(false)
  const { pushToast } = useToast()

  async function onCopy() {
    if (!value || disabled) return
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      pushToast(successMessage, 'success')
      window.setTimeout(() => setCopied(false), 1300)
    } catch {
      pushToast('Unable to access clipboard', 'error')
    }
  }

  return (
    <button
      type="button"
      onClick={onCopy}
      disabled={disabled || !value}
      className={cn(
        'inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-mono transition-colors',
        'border-white/15 text-gray-200 hover:bg-white/5 disabled:opacity-40 disabled:cursor-not-allowed',
        className,
      )}
    >
      {copied ? <Check size={13} className="text-green-300" /> : <Copy size={13} />}
      {copied ? 'Copied' : label}
    </button>
  )
}
