// DNS-over-HTTPS client for the dns.google JSON API (also Cloudflare's /dns-query
// with a compatible shape). Works in the browser — dns.google sends CORS headers —
// and in Node, so the snapshot builder and the /dns page share one implementation.

import type { DnssecStatus } from '../api/types'

export const DEFAULT_RESOLVER = 'https://dns.google/resolve'

export interface DohRecord {
  name: string
  /** Numeric RR type (1 = A, 257 = CAA, ...). */
  type: number
  TTL: number
  data: string
}

export interface DohResponse {
  /** RCODE: 0 NOERROR, 2 SERVFAIL, 3 NXDOMAIN, ... */
  Status: number
  /** Authenticated Data — resolver validated DNSSEC on this answer. */
  AD: boolean
  Answer?: DohRecord[]
}

export async function dohQuery(name: string, type: string, { cd = false, resolver = DEFAULT_RESOLVER }: { cd?: boolean; resolver?: string } = {}): Promise<DohResponse | null> {
  try {
    const res = await fetch(`${resolver}?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}${cd ? '&cd=1' : ''}`, { signal: AbortSignal.timeout(10_000) })
    return res.ok ? ((await res.json()) as DohResponse) : null
  } catch {
    return null
  }
}

export interface DnssecResult {
  status: DnssecStatus | null
  /** The queried name does not exist (authenticated or unsigned denial). */
  nxdomain: boolean
}

/**
 * DNSSEC state of `name` as seen by a validating resolver. `valid` covers
 * authenticated NOERROR and authenticated denials; `broken` means the zone is
 * signed but fails validation (a plain lookup SERVFAILs while a check-disabled
 * retry succeeds); `unsigned` is the common case of a zone without DNSSEC.
 * `null` = could not determine.
 */
export async function dnssecStatus(name: string, resolver?: string): Promise<DnssecResult> {
  const a = await dohQuery(name, 'A', { resolver })
  if (!a) return { status: null, nxdomain: false }
  if (a.AD) return { status: 'valid', nxdomain: a.Status === 3 }
  if (a.Status === 0) return { status: 'unsigned', nxdomain: false }
  if (a.Status === 3) return { status: 'unsigned', nxdomain: true }
  if (a.Status === 2) {
    const b = await dohQuery(name, 'A', { cd: true, resolver })
    if (b && (b.Status === 0 || b.Status === 3)) return { status: 'broken', nxdomain: false }
  }
  return { status: null, nxdomain: false }
}

export interface CaaResult {
  /** true = at least one CAA record constrains issuance; null = could not determine. */
  found: boolean | null
  /** The name the records were found at (the queried name or an ancestor). */
  at: string | null
  records: string[]
}

/**
 * Effective CAA records for `name`: queries the name itself, then climbs parent
 * labels (down to a 2-label registrable domain) until a CAA answer appears — a
 * subdomain is constrained by the nearest ancestor's CAA policy.
 */
export async function caaRecords(name: string, resolver?: string): Promise<CaaResult> {
  const labels = name.replace(/\.$/, '').split('.')
  let anyResponse = false
  for (let i = 0; i <= labels.length - 2; i++) {
    const candidate = labels.slice(i).join('.')
    const r = await dohQuery(candidate, 'CAA', { resolver })
    if (!r) continue
    anyResponse = true
    const records = (r.Answer ?? []).filter((x) => x.type === 257).map((x) => x.data)
    if (records.length) return { found: true, at: candidate, records }
  }
  return { found: anyResponse ? false : null, at: null, records: [] }
}
