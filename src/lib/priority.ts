import type { Confidence, Finding, PriorityBreakdown, Severity } from '../api/types.ts'

// Default weights from Specification.md FR5. Kept in sync with the backend config.
export const PRIORITY_WEIGHTS = {
  severity: 35,
  criticality: 25,
  exploitability: 15,
  exposure: 10,
  fix_available: 10,
  confidence_penalty: 15,
} as const

const CONFIDENCE_PENALTY: Record<Confidence, number> = { confirmed: 0, possible: 0.5, inferred: 1 }

// Used only when an advisory has no computable CVSS score.
export const SEVERITY_NORM: Record<Severity, number> = { critical: 0.95, high: 0.8, medium: 0.55, low: 0.25, unknown: 0.4 }

export interface PriorityInput {
  severity: Severity
  cvss: number | null
  /** 0–1, log-normalized PG Atlas criticality of the affected repo */
  criticality: number
  kev: boolean
  epss: number | null
  /** 0–1, log-normalized count of downstream repos that depend on the affected repo */
  reach: number
  fixAvailable: boolean
  confidence: Confidence
}

export const logNorm = (value: number | null, max: number) => (value && max > 0 ? Math.log1p(value) / Math.log1p(max) : 0)

export function computePriority(i: PriorityInput): { priority: number; breakdown: PriorityBreakdown } {
  const w = PRIORITY_WEIGHTS
  const breakdown: PriorityBreakdown = {
    severity: w.severity * (i.cvss != null ? i.cvss / 10 : SEVERITY_NORM[i.severity]),
    criticality: w.criticality * i.criticality,
    exploitability: w.exploitability * (i.kev ? 1 : (i.epss ?? 0)),
    exposure: w.exposure * i.reach,
    fix_available: w.fix_available * (i.fixAvailable ? 1 : 0),
    confidence_penalty: -w.confidence_penalty * CONFIDENCE_PENALTY[i.confidence],
  }
  const total = Object.values(breakdown).reduce((a, b) => a + b, 0)
  return { priority: Math.round(Math.max(0, Math.min(100, total))), breakdown }
}

// "Needs action" gate — replaces raw CVE presence/counts as the project flag. A
// finding is actionable only with applicability/exploit evidence (KEV, a confirmed
// call path into vulnerable code, high EPSS) or once a fixable issue has gone
// unpatched past the grace window; fresh criticals flag early so they don't linger.
// Cleared reachability verdicts (not-called/unflagged), inferred edges and
// non-vulnerability advisory kinds (unmaintained/notice/…) never flag a project.
export const ACTIONABLE = {
  /** EPSS at or above which a fixable finding counts as exploited-evidence. */
  EPSS: 0.2,
  /** Fixable findings unpatched longer than this flag remediation latency. */
  FIXABLE_GRACE_DAYS: 90,
  /** Fresh criticals flag early even without a fix or exploit evidence. */
  CRITICAL_GRACE_DAYS: 14,
} as const

// Dojo triage states that clear the flag — a WG decision carries the same
// weight as a 'not-called' verdict.
const DOJO_CLEARED = new Set(['false_positive', 'risk_accepted', 'out_of_scope', 'mitigated', 'duplicate'])

type ActionableFinding = Pick<Finding, 'status' | 'kind' | 'kev' | 'epss' | 'reachability' | 'confidence' | 'severity' | 'fixed_versions' | 'advisory_published' | 'dojo_status'>

export function isActionable(f: ActionableFinding, now: number): boolean {
  if (f.status !== 'open') return false
  if (f.dojo_status && DOJO_CLEARED.has(f.dojo_status)) return false
  const kind = f.kind ?? 'vulnerability'
  if (kind === 'malware') return true
  if (kind !== 'vulnerability') return false
  if (f.kev || f.reachability === 'called') return true
  if (f.reachability === 'not-called' || f.reachability === 'unflagged') return false
  if (f.confidence === 'inferred') return false
  const fixable = f.fixed_versions.length > 0
  const age = f.advisory_published ? (now - Date.parse(f.advisory_published)) / 86_400_000 : null
  return (fixable && (f.epss ?? 0) >= ACTIONABLE.EPSS) || (fixable && age != null && age > ACTIONABLE.FIXABLE_GRACE_DAYS) || (f.severity === 'critical' && age != null && age > ACTIONABLE.CRITICAL_GRACE_DAYS)
}

/** Days since the advisory was published, floored; null when no publish date. */
export const actionableAgeDays = (f: Pick<Finding, 'advisory_published'>, now: number) => (f.advisory_published ? Math.max(0, Math.floor((now - Date.parse(f.advisory_published)) / 86_400_000)) : null)
