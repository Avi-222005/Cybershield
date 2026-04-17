import { type ElementType } from 'react'

type ToolHeaderProps = {
  icon: ElementType
  title: string
  description: string
}

export default function ToolHeader({ icon: Icon, title, description }: ToolHeaderProps) {
  return (
    <div className="mb-8">
      <div className="flex items-center gap-2.5 mb-2">
        <div className="p-2 rounded-lg bg-[#0d6efd]/10 border border-[#0d6efd]/20">
          <Icon size={18} className="text-[#0d6efd]" />
        </div>
        <h1 className="text-2xl font-bold text-white">{title}</h1>
      </div>
      <p className="text-gray-500 text-sm ml-10">{description}</p>
    </div>
  )
}
