import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function getVerdictColor(verdict: string): string {
  const v = verdict?.toUpperCase()
  if (v === 'SAFE' || v === 'CLEAN') return '#22c55e'
  if (v === 'SUSPICIOUS') return '#f59e0b'
  if (v === 'MALICIOUS') return '#ef4444'
  return '#9ca3af'
}

export function getSeverityColor(severity: string): string {
  const s = severity?.toLowerCase()
  if (s === 'low') return '#22c55e'
  if (s === 'medium') return '#f59e0b'
  if (s === 'high') return '#f97316'
  if (s === 'critical') return '#ef4444'
  return '#9ca3af'
}

export function getScoreColor(score: number): string {
  if (score < 30) return '#22c55e'
  if (score < 60) return '#f59e0b'
  if (score < 80) return '#f97316'
  return '#ef4444'
}
