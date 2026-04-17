import { ReactNode } from 'react'

type ResultCardProps = {
  title: string
  description?: string
  actions?: ReactNode
  children: ReactNode
}

export default function ResultCard({ title, description, actions, children }: ResultCardProps) {
  return (
    <section className="glass-card rounded-2xl p-5 border border-white/10">
      <div className="flex items-start justify-between gap-3 mb-3">
        <div>
          <h2 className="text-sm font-semibold text-white">{title}</h2>
          {description && <p className="text-xs text-gray-500 font-mono mt-1">{description}</p>}
        </div>
        {actions && <div className="shrink-0">{actions}</div>}
      </div>
      <div>{children}</div>
    </section>
  )
}
