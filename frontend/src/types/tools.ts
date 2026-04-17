export type HashAlgorithm = 'MD5' | 'SHA1' | 'SHA256' | 'SHA512' | 'SHA3-256' | 'SHA3-512' | 'BLAKE2'

export interface HashAlgorithmOption {
  value: HashAlgorithm
  label: string
  available: boolean
  details?: string
}

export interface TextHashResult {
  algorithm: HashAlgorithm
  hash: string
  length: number
}

export interface FileHashResult {
  fileName: string
  fileSize: number
  sha256: string
  sha512: string
  md5?: string
}

export interface PasswordGeneratorConfig {
  length: number
  includeUppercase: boolean
  includeLowercase: boolean
  includeNumbers: boolean
  includeSymbols: boolean
  excludeSimilar: boolean
  avoidAmbiguousSymbols: boolean
}

export type PasswordStrengthLevel = 'Weak' | 'Medium' | 'Strong' | 'Very Strong'

export interface PasswordStrengthResult {
  entropyBits: number
  level: PasswordStrengthLevel
  scorePercent: number
}

export interface DecodedJwt {
  header: Record<string, unknown>
  payload: Record<string, unknown>
  signature: string
  issuedAtReadable: string | null
  expiresAtReadable: string | null
  isExpired: boolean | null
  warnings: string[]
}

export type HashConfidence = 'High' | 'Medium' | 'Low'

export interface HashIdentifierMatch {
  type: string
  confidence: HashConfidence
  notes?: string
}

export interface HashIdentifierResult {
  normalized: string
  length: number
  charset: string
  prefix: string | null
  matches: HashIdentifierMatch[]
}
