import { blake2b, md5, sha1, sha256, sha3, sha512 } from 'hash-wasm'
import type {
  DecodedJwt,
  FileHashResult,
  HashAlgorithm,
  HashAlgorithmOption,
  HashIdentifierResult,
  PasswordGeneratorConfig,
  PasswordStrengthResult,
} from '../types/tools'

const TEXT_ENCODER = new TextEncoder()
const TEXT_DECODER = new TextDecoder()

const SIMILAR_CHARS = new Set(['O', '0', 'l', '1', 'I'])
const AMBIGUOUS_SYMBOLS = new Set(['{', '}', '[', ']', '(', ')', '/', '\\', '"', "'", ',', ';', ':', '.', '<', '>'])

const UPPERCASE_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
const LOWERCASE_CHARS = 'abcdefghijklmnopqrstuvwxyz'
const NUMBER_CHARS = '0123456789'
const SYMBOL_CHARS = '!@#$%^&*()-_=+[]{};:,.<>?/|~'

export const TEXT_HASH_ALGORITHMS: HashAlgorithmOption[] = [
  { value: 'MD5', label: 'MD5', available: true },
  { value: 'SHA1', label: 'SHA1', available: true },
  { value: 'SHA256', label: 'SHA256', available: true },
  { value: 'SHA512', label: 'SHA512', available: true },
  { value: 'SHA3-256', label: 'SHA3-256', available: true },
  { value: 'SHA3-512', label: 'SHA3-512', available: true },
  { value: 'BLAKE2', label: 'BLAKE2 (256-bit)', available: true, details: 'blake2b-256' },
]

function bufferToHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

function normalizeBase64(base64: string): string {
  const stripped = base64.replace(/\s+/g, '')
  const padding = stripped.length % 4
  if (padding === 0) return stripped
  if (padding === 2) return `${stripped}==`
  if (padding === 3) return `${stripped}=`
  return stripped
}

function base64ToUint8Array(base64: string): Uint8Array {
  const binary = atob(base64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

function uint8ArrayToBase64(data: Uint8Array): string {
  let binary = ''
  const chunkSize = 0x8000
  for (let i = 0; i < data.length; i += chunkSize) {
    const chunk = data.subarray(i, i + chunkSize)
    binary += String.fromCharCode(...chunk)
  }
  return btoa(binary)
}

function decodeBase64UrlJson(segment: string): Record<string, unknown> {
  const normalized = normalizeBase64(segment.replace(/-/g, '+').replace(/_/g, '/'))
  const bytes = base64ToUint8Array(normalized)
  const json = TEXT_DECODER.decode(bytes)
  return JSON.parse(json) as Record<string, unknown>
}

function getCharsetLabel(hash: string): string {
  if (/^[0-9a-f]+$/i.test(hash)) return 'Hexadecimal'
  if (/^[A-Za-z0-9+/=]+$/.test(hash)) return 'Base64-like'
  if (/^[A-Za-z0-9./$]+$/.test(hash)) return 'Modular crypt format'
  return 'Mixed / Unknown'
}

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  const exponent = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1)
  const value = bytes / 1024 ** exponent
  return `${value.toFixed(exponent === 0 ? 0 : 2)} ${units[exponent]}`
}

export async function hashText(input: string, algorithm: HashAlgorithm): Promise<string> {
  switch (algorithm) {
    case 'MD5':
      return md5(input)
    case 'SHA1':
      return sha1(input)
    case 'SHA256':
      return sha256(input)
    case 'SHA512':
      return sha512(input)
    case 'SHA3-256':
      return sha3(input, 256)
    case 'SHA3-512':
      return sha3(input, 512)
    case 'BLAKE2':
      return blake2b(input, 256)
    default:
      return sha256(input)
  }
}

export async function hashFileInBrowser(file: File): Promise<FileHashResult> {
  const buffer = await file.arrayBuffer()

  const sha256Digest = await crypto.subtle.digest('SHA-256', buffer)
  const sha512Digest = await crypto.subtle.digest('SHA-512', buffer)

  // Optional non-WebCrypto digest to provide MD5 as requested.
  const md5Digest = await md5(new Uint8Array(buffer))

  return {
    fileName: file.name,
    fileSize: file.size,
    sha256: bufferToHex(sha256Digest),
    sha512: bufferToHex(sha512Digest),
    md5: md5Digest,
  }
}

export function downloadTextReport(fileName: string, content: string): void {
  const blob = new Blob([content], { type: 'text/plain;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = fileName
  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()
  URL.revokeObjectURL(url)
}

function buildPool(config: PasswordGeneratorConfig): string {
  let pool = ''

  if (config.includeUppercase) pool += UPPERCASE_CHARS
  if (config.includeLowercase) pool += LOWERCASE_CHARS
  if (config.includeNumbers) pool += NUMBER_CHARS
  if (config.includeSymbols) pool += SYMBOL_CHARS

  if (config.excludeSimilar) {
    pool = pool
      .split('')
      .filter((char) => !SIMILAR_CHARS.has(char))
      .join('')
  }

  if (config.avoidAmbiguousSymbols) {
    pool = pool
      .split('')
      .filter((char) => !AMBIGUOUS_SYMBOLS.has(char))
      .join('')
  }

  return Array.from(new Set(pool.split(''))).join('')
}

function randomInt(maxExclusive: number): number {
  const random = new Uint32Array(1)
  crypto.getRandomValues(random)
  return random[0] % maxExclusive
}

export function generatePassword(config: PasswordGeneratorConfig): string {
  const pool = buildPool(config)
  if (!pool) {
    throw new Error('Enable at least one character set to generate a password.')
  }

  let output = ''
  for (let i = 0; i < config.length; i += 1) {
    output += pool[randomInt(pool.length)]
  }
  return output
}

export function estimatePasswordStrength(password: string): PasswordStrengthResult {
  if (!password) {
    return { entropyBits: 0, level: 'Weak', scorePercent: 0 }
  }

  let poolSize = 0
  if (/[A-Z]/.test(password)) poolSize += 26
  if (/[a-z]/.test(password)) poolSize += 26
  if (/[0-9]/.test(password)) poolSize += 10
  if (/[^A-Za-z0-9]/.test(password)) poolSize += 33

  const entropyBits = Math.max(0, Math.round(password.length * Math.log2(Math.max(poolSize, 1))))

  if (entropyBits < 40) return { entropyBits, level: 'Weak', scorePercent: 25 }
  if (entropyBits < 60) return { entropyBits, level: 'Medium', scorePercent: 55 }
  if (entropyBits < 80) return { entropyBits, level: 'Strong', scorePercent: 78 }
  return { entropyBits, level: 'Very Strong', scorePercent: 96 }
}

export function encodeUtf8Base64(input: string): string {
  const bytes = TEXT_ENCODER.encode(input)
  return uint8ArrayToBase64(bytes)
}

export function decodeUtf8Base64(input: string): string {
  const normalized = normalizeBase64(input)
  const bytes = base64ToUint8Array(normalized)
  return TEXT_DECODER.decode(bytes)
}

export function isLikelyBase64(input: string): boolean {
  const trimmed = input.trim()
  if (!trimmed || trimmed.length % 4 === 1) return false
  return /^[A-Za-z0-9+/\s=_-]+$/.test(trimmed)
}

export function decodeJwtToken(token: string): DecodedJwt {
  const cleaned = token.trim()
  const parts = cleaned.split('.')
  if (parts.length < 2) {
    throw new Error('Invalid JWT format. Expected header.payload.signature')
  }

  const header = decodeBase64UrlJson(parts[0])
  const payload = decodeBase64UrlJson(parts[1])
  const signature = parts[2] || ''

  const exp = typeof payload.exp === 'number' ? payload.exp : null
  const iat = typeof payload.iat === 'number' ? payload.iat : null

  const now = Math.floor(Date.now() / 1000)
  const isExpired = exp === null ? null : now >= exp

  const warnings: string[] = []
  if (String(header.alg || '').toLowerCase() === 'none') {
    warnings.push('Token uses alg=none. This is insecure in production contexts.')
  }
  if (exp === null) {
    warnings.push('Token is missing exp claim.')
  }
  if (isExpired) {
    warnings.push('Token has expired.')
  }
  if (exp !== null && iat !== null) {
    const lifetime = exp - iat
    if (lifetime > 60 * 60 * 24 * 30) {
      warnings.push('Token validity window is unusually long.')
    }
  }

  return {
    header,
    payload,
    signature,
    issuedAtReadable: iat ? new Date(iat * 1000).toLocaleString() : null,
    expiresAtReadable: exp ? new Date(exp * 1000).toLocaleString() : null,
    isExpired,
    warnings,
  }
}

export function identifyHash(input: string): HashIdentifierResult {
  const normalized = input.trim()
  const lower = normalized.toLowerCase()
  const length = normalized.length
  const matches: HashIdentifierResult['matches'] = []

  const addMatch = (type: string, confidence: 'High' | 'Medium' | 'Low', notes?: string) => {
    matches.push({ type, confidence, notes })
  }

  if (/^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/.test(normalized)) {
    addMatch('bcrypt', 'High', 'Prefix indicates bcrypt format')
  }

  if (/^\$argon2(id|i|d)\$/.test(normalized)) {
    addMatch('Argon2', 'High', 'Prefix indicates Argon2 format')
  }

  if (/^[0-9a-f]+$/i.test(normalized)) {
    if (length === 32) {
      addMatch('MD5', 'High')
      addMatch('NTLM', 'Medium', 'NTLM hashes are also 32 hex chars')
    }
    if (length === 40) {
      addMatch('SHA1', 'High')
    }
    if (length === 56) {
      addMatch('SHA224', 'High')
    }
    if (length === 64) {
      addMatch('SHA256', 'High')
      addMatch('SHA3-256', 'Medium')
      addMatch('BLAKE2s-256', 'Medium')
      addMatch('HMAC-SHA256', 'Low', 'May represent keyed digest output')
    }
    if (length === 96) {
      addMatch('SHA384', 'High')
    }
    if (length === 128) {
      addMatch('SHA512', 'High')
      addMatch('SHA3-512', 'Medium')
      addMatch('BLAKE2b-512', 'Medium')
      addMatch('Whirlpool', 'Low')
    }
  }

  if (matches.length === 0) {
    addMatch('Unknown', 'Low', 'No strong signature match found')
  }

  return {
    normalized: lower,
    length,
    charset: getCharsetLabel(normalized),
    prefix: normalized.startsWith('$') ? normalized.split('$').slice(0, 2).join('$') + '$' : null,
    matches,
  }
}
