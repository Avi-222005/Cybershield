import { type ElementType } from 'react'
import { Inbox } from 'lucide-react'

type EmptyStateProps = {
  title: string
  description: string
  icon?: ElementType
}

export default function EmptyState({ title, description, icon: Icon = Inbox }: EmptyStateProps) {
  return (
    <div className="rounded-xl border border-white/10 bg-white/3 px-4 py-6 text-center">
      <div className="inline-flex p-2 rounded-lg border border-white/15 bg-white/5 mb-2">
        <Icon size={16} className="text-gray-400" />
      </div>
      <p className="text-sm text-gray-200 mb-1">{title}</p>
      <p className="text-xs text-gray-500 font-mono">{description}</p>
    </div>
  )
}
