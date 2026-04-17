import { ReactNode, useState } from 'react'
import { ChevronDown, ChevronUp } from 'lucide-react'

type Props = {
  title: string
  subtitle?: string
  badge?: ReactNode
  defaultOpen?: boolean
  children: ReactNode
}

export default function CollapsibleModuleCard({
  title,
  subtitle,
  badge,
  defaultOpen = false,
  children,
}: Props) {
  const [open, setOpen] = useState(defaultOpen)

  return (
    <div className="rounded-xl border border-white/10 bg-white/3">
      <button
        type="button"
        onClick={() => setOpen((prev) => !prev)}
        className="w-full px-4 py-3 text-left flex items-center justify-between gap-3"
      >
        <div className="min-w-0">
          <div className="text-sm font-semibold text-white truncate">{title}</div>
          {subtitle && <div className="text-xs text-gray-500 font-mono mt-0.5 truncate">{subtitle}</div>}
        </div>

        <div className="flex items-center gap-2 shrink-0">
          {badge}
          {open ? <ChevronUp size={16} className="text-gray-500" /> : <ChevronDown size={16} className="text-gray-500" />}
        </div>
      </button>

      {open && <div className="px-4 pb-4 border-t border-white/10">{children}</div>}
    </div>
  )
}
