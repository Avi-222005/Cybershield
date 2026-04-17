import { AlertTriangle } from 'lucide-react'

type ErrorAlertProps = {
  message: string
}

export default function ErrorAlert({ message }: ErrorAlertProps) {
  return (
    <div className="rounded-lg border border-red-500/25 bg-red-500/5 text-red-300 px-3 py-2 text-sm font-mono flex items-start gap-2">
      <AlertTriangle size={14} className="mt-0.5 shrink-0" />
      <span>{message}</span>
    </div>
  )
}
