import type { PasswordStrengthLevel } from '../../../types/tools'

type StrengthBadgeProps = {
  level: PasswordStrengthLevel
}

function badgeStyles(level: PasswordStrengthLevel): string {
  if (level === 'Weak') return 'text-red-300 border-red-500/35 bg-red-500/10'
  if (level === 'Medium') return 'text-amber-300 border-amber-500/35 bg-amber-500/10'
  if (level === 'Strong') return 'text-cyan-300 border-cyan-500/35 bg-cyan-500/10'
  return 'text-green-300 border-green-500/35 bg-green-500/10'
}

export default function StrengthBadge({ level }: StrengthBadgeProps) {
  return (
    <span className={`text-xs px-2.5 py-1 rounded border font-mono ${badgeStyles(level)}`}>
      {level}
    </span>
  )
}
