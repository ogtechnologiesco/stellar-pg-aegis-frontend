import type { ProjectDetail } from '../src/api/types.ts'
import { actionableAgeDays, isActionable } from '../src/lib/priority.ts'

// Recomputes the needs-action gate on every finding and rolls up per-project
// counts + oldest age. Called by the annotate/review recounts after reachability
// or manual-verdict changes so `actionable` never goes stale. Returns the
// ecosystem total for `summary.actionable_findings`.
export function recountActionable(projects: ProjectDetail[], now: number): number {
  let total = 0
  for (const p of projects) {
    let oldest: number | null = null
    let n = 0
    for (const f of p.findings) {
      f.actionable = isActionable(f, now)
      if (!f.actionable) continue
      n++
      const age = actionableAgeDays(f, now)
      if (age != null) oldest = Math.max(oldest ?? 0, age)
    }
    p.actionable_findings = n
    p.oldest_actionable_age_days = oldest
    total += n
  }
  return total
}
