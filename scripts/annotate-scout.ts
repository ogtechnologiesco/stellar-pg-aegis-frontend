/**
 * Runs the Scout (CoinFabrik) Soroban contract-lint pass against the existing
 * `public/data/snapshot.json` without a full PG Atlas refresh — the same pass
 * build-snapshot.ts runs, but standalone so contract-lint coverage can be
 * added/updated cheaply.
 *
 * Detects soroban-sdk manifests in WG-listed repos (highest criticality first),
 * runs `cargo scout-audit` in the coinfabrik/scout container (x86_64) or a local
 * binary with a secrets-stripped env (arm64), and merges findings into
 * `sast_findings` tagged tool:'scout' — Semgrep entries are preserved.
 *
 * Usage: node scripts/annotate-scout.ts
 * Env:   SCOUT=0 disables, SCOUT_MAX_REPOS=<n> caps cloned repos,
 *        SCOUT_REPOS=owner/name,... restricts targets,
 *        SCOUT_RUNNER=docker|local|auto picks the runner,
 *        SCOUT_VERSION pins the tool/image tag (default 0.3.17)
 */
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import type { SastFinding, Snapshot } from '../src/api/types.ts'
import { CACHE_DIR, log } from './cache.ts'
import { ghKey, ghRepoOf } from './govulncheck.ts'
import { scoutRepo, scoutRunner, SCOUT_MAX, SCOUT_REPOS, SCOUT_VERSION } from './scout.ts'

const OUT = resolve(dirname(fileURLToPath(import.meta.url)), '../public/data/snapshot.json')

async function main() {
  const snap = JSON.parse(await readFile(OUT, 'utf8')) as Snapshot
  const targets = snap.projects
    .filter((p) => p.wg_listed)
    .flatMap((p) => p.repos.map((r) => ({ p, r, gh: ghRepoOf(r.repo_url) })))
    .filter((x): x is { p: (typeof snap.projects)[number]; r: (typeof snap.projects)[number]['repos'][number]; gh: { owner: string; name: string } } => !!x.gh && !!x.r.repo_url && (!SCOUT_REPOS || SCOUT_REPOS.includes(ghKey(x.gh))))
    .sort((a, b) => (b.r.criticality_score ?? 0) - (a.r.criticality_score ?? 0))
    .slice(0, SCOUT_MAX)
  if (!targets.length) {
    log('no WG-listed GitHub repos in the snapshot — nothing to scan')
    return
  }
  const run = await scoutRunner()
  if (!run) {
    log('scout: no runner available (docker or cargo-scout-audit) — aborting')
    process.exit(1)
  }
  log(`scout ${SCOUT_VERSION} via ${run.kind}: checking ${targets.length} WG-listed repos for Soroban contracts${Number.isFinite(SCOUT_MAX) ? ' (capped)' : ''}`)
  const byProject = new Map<string, SastFinding[]>()
  const sev = { error: 0, warning: 0, info: 0 }
  let scanned = 0
  let contracts = 0
  for (const { p, r, gh } of targets) {
    const res = await scoutRepo(run, gh, r.repo_url!, { repo_id: r.canonical_id, repo_name: r.display_name, project_id: p.canonical_id, project_name: p.display_name })
    if (!res || !res.contract) continue
    scanned++
    contracts++
    for (const f of res.findings) {
      sev[f.severity]++
      const list = byProject.get(p.canonical_id) ?? []
      list.push(f)
      byProject.set(p.canonical_id, list)
    }
  }
  const targeted = new Set(targets.map((t) => t.p.canonical_id))
  const sevOrder = { error: 0, warning: 1, info: 2 }
  for (const p of snap.projects) {
    if (!targeted.has(p.canonical_id)) continue
    // Replace only scout findings — semgrep entries survive.
    const others = (p.sast_findings ?? []).filter((f) => f.tool !== 'scout')
    p.sast_findings = [...others, ...(byProject.get(p.canonical_id) ?? [])]
    p.sast_findings.sort((a, b) => a.repo_id.localeCompare(b.repo_id) || sevOrder[a.severity] - sevOrder[b.severity])
  }
  snap.summary.scout = { tool_version: SCOUT_VERSION, runner: run.kind, repos_targeted: targets.length, repos_scanned: scanned, contracts_found: contracts, findings: sev }
  if (scanned && !snap.summary.sources.includes('Scout')) snap.summary.sources.push('Scout')
  await mkdir(dirname(OUT), { recursive: true })
  await mkdir(CACHE_DIR, { recursive: true })
  await writeFile(OUT, JSON.stringify(snap))
  log(`wrote ${OUT} — ${contracts}/${targets.length} contract repos (${scanned} analyzed) · ${sev.error} errors / ${sev.warning} warnings / ${sev.info} info`)
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
