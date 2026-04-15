/// <reference types="vite/client" />
import { createClient } from '@supabase/supabase-js'

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL as string
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY as string

// Supabase client — only created when env vars are configured
export const supabase =
  supabaseUrl && supabaseAnonKey
    ? createClient(supabaseUrl, supabaseAnonKey)
    : null

export type ScanType = 'url_phishing' | 'ip_reputation' | 'ssl_certificate' | 'whois'

export async function saveScanResult(
  scanType: ScanType,
  target: string,
  result: Record<string, unknown>,
) {
  if (!supabase) return null
  const { data, error } = await supabase.from('scan_results').insert({
    scan_type: scanType,
    target,
    result: JSON.stringify(result),
    created_at: new Date().toISOString(),
  })
  if (error) console.warn('Supabase save failed:', error.message)
  return data
}
