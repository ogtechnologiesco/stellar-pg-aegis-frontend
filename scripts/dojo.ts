/**
 * Syncs snapshot findings with a DefectDojo OSS instance — the WG's internal
 * triage + SLA backend. DefectDojo itself never reaches the public dashboard;
 * only its triage decisions flow back onto findings.
 *
 *   node scripts/dojo.ts push   create the hierarchy and reimport-scan each
 *                               repo's findings (Generic Findings Import; dedup
 *                               via unique_id_from_tool = Aegis finding id;
 *                               close_old_findings marks resolved advisories as
 *                               mitigated in Dojo).
 *   node scripts/dojo.ts pull   read Dojo triage state (status + SLA countdown)
 *                               back onto snapshot.json findings, then recount
 *                               the needs-action gate (triaged states clear it).
 *
 * Hierarchy: Product Type "Stellar Public Goods" → Product per Aegis project
 * (tagged aegis:<canonical_id>) → ongoing Engagement "aegis-scan" → Test per repo
 * (title = repo canonical_id) so close_old_findings stays scoped per repo.
 *
 * Dedup requires the instance to honor unique_id_from_tool for Generic imports —
 * set on the Dojo deployment (see deploy/dojo/README.md):
 *   DD_DEDUPLICATION_ALGORITHM_PER_PARSER={"Generic Findings Import":"unique_id_from_tool_or_hash_code"}
 *
 * Env: DOJO_URL (e.g. http://localhost:8080), DOJO_API_KEY (API v2 token),
 *      DOJO_PRODUCT_TYPE (default "Stellar Public Goods"), DOJO_DRY_RUN=1
 *      (print actions, write nothing), DOJO_LIMIT=<n> (cap repos pushed),
 *      DOJO_PROJECTS=<id,id,…> (restrict to projects).
 */
import { readFile, writeFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import type { DojoStatus, Finding, Severity, Snapshot } from '../src/api/types.ts'
import { recountActionable } from './actionable.ts'
import { CACHE_DIR, log } from './cache.ts'

const OUT = resolve(dirname(fileURLToPath(import.meta.url)), '../public/data/snapshot.json')
const MAP_PATH = resolve(CACHE_DIR, 'dojo-map.json')
const SITE = 'https://stellar-pg-aegis.netlify.app'

const DOJO_URL = (process.env.DOJO_URL ?? '').replace(/\/$/, '')
const DOJO_KEY = process.env.DOJO_API_KEY ?? ''
const PRODUCT_TYPE = process.env.DOJO_PRODUCT_TYPE ?? 'Stellar Public Goods'
const DRY_RUN = process.env.DOJO_DRY_RUN === '1'
const LIMIT = Number(process.env.DOJO_LIMIT ?? Infinity)
const ONLY_PROJECTS = process.env.DOJO_PROJECTS ? new Set(process.env.DOJO_PROJECTS.split(',').filter(Boolean)) : null
const ENGAGEMENT_NAME = 'aegis-scan'
const SCAN_TYPE = 'Generic Findings Import'
const TAG = (id: string) => `aegis:${id}`

// ---------------------------------------------------------------------------
// API client

async function api<T>(path: string, init: { method?: string; json?: unknown; form?: FormData } = {}): Promise<T> {
  const res = await fetch(`${DOJO_URL}/api/v2${path}`, {
    method: init.method ?? 'GET',
    headers: { Authorization: `Token ${DOJO_KEY}`, ...(init.json ? { 'Content-Type': 'application/json' } : {}) },
    body: init.json ? JSON.stringify(init.json) : init.form,
  })
  if (!res.ok) throw new Error(`${init.method ?? 'GET'} ${path} → ${res.status}: ${(await res.text()).slice(0, 300)}`)
  return res.status === 204 ? (undefined as T) : res.json() as Promise<T>
}

async function listAll<T>(path: string): Promise<T[]> {
  const out: T[] = []
  let next: string | null = `${DOJO_URL}/api/v2${path}`
  while (next) {
    const page: { results: T[]; next: string | null } = await api(next.replace(`${DOJO_URL}/api/v2`, ''))
    out.push(...page.results)
    next = page.next
  }
  return out
}

const pool = async <T, R>(items: T[], n: number, fn: (x: T) => Promise<R>): Promise<R[]> => {
  const out: R[] = new Array(items.length)
  let i = 0
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => {
    while (i < items.length) {
      const k = i++
      out[k] = await fn(items[k])
    }
  }))
  return out
}

// ---------------------------------------------------------------------------
// Types for the subset of Dojo objects we touch

type Id = number
type DojoProduct = { id: Id; name: string; tags: string[] }
type DojoEngagement = { id: Id; name: string; product: Id }
type DojoTest = { id: Id; title: string; engagement: Id }
type DojoFinding = {
  id: Id
  unique_id_from_tool: string | null
  active: boolean
  verified: boolean
  false_p: boolean
  out_of_scope: boolean
  risk_accepted: boolean
  is_mitigated: boolean
  duplicate: boolean
  sla_days_remaining: number | null
}

type DojoMap = { product: Record<string, Id>; engagement: Record<string, Id>; test: Record<string, Id> }
const loadMap = async (): Promise<DojoMap> => JSON.parse(await readFile(MAP_PATH, 'utf8').catch(() => '{"product":{},"engagement":{},"test":{}}')) as DojoMap
const saveMap = (m: DojoMap) => writeFile(MAP_PATH, JSON.stringify(m))

// ---------------------------------------------------------------------------
// Generic Findings Import serialization (dojo/tools/generic/json_parser.py)

const SEV: Record<Severity, string> = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', unknown: 'Info' }

function toGeneric(f: Finding, vulnAliases: Map<string, string[]>, generatedAt: string) {
  const cve = (vulnAliases.get(f.vuln_id) ?? []).find((a) => a.startsWith('CVE-')) ?? (f.vuln_id.startsWith('CVE-') ? f.vuln_id : undefined)
  const tags = [
    'aegis',
    `confidence:${f.confidence}`,
    `src:${f.source}`,
    `eco:${f.package.ecosystem.toLowerCase()}`,
    ...(f.kind && f.kind !== 'vulnerability' ? [`kind:${f.kind}`] : []),
    ...(f.reachability ? [`reach:${f.reachability}`] : []),
    ...(f.actionable ? ['aegis:actionable'] : []),
  ]
  return {
    title: `${f.vuln_id} · ${f.package.name}@${f.package.version} · ${f.repo_name}`,
    date: (f.advisory_published ?? generatedAt).slice(0, 10),
    severity: SEV[f.severity],
    description: [
      f.summary,
      '',
      `Repo: ${f.repo_name} (${f.repo_id})`,
      `Aegis: confidence=${f.confidence} · source=${f.source} · priority=${f.priority}${f.reachability ? ` · reachability=${f.reachability}` : ''}`,
      `Advisory & blast radius: ${SITE}/advisories/${f.vuln_id}`,
    ].join('\n'),
    mitigation: f.fixed_versions.length ? `Upgrade ${f.package.name} to ${f.fixed_versions[0]} or later.${f.upgrade_hint ? `\n${f.upgrade_hint}` : ''}` : 'No patched version is available — see the advisory for workarounds.',
    references: `${SITE}/advisories/${f.vuln_id}`,
    active: true,
    verified: false,
    static_finding: true,
    dynamic_finding: false,
    unique_id_from_tool: f.id,
    vuln_id_from_tool: f.vuln_id,
    component_name: f.package.name,
    component_version: f.package.version,
    purl: f.package.purl,
    ...(cve ? { cve } : {}),
    ...(f.cvss != null ? { cvssv3_score: f.cvss } : {}),
    ...(f.epss != null ? { epss_score: f.epss } : {}),
    ...(f.fixed_versions.length ? { fix_available: true, fix_version: f.fixed_versions[0] } : {}),
    ...(f.kev ? { known_exploited: true } : {}),
    tags,
  }
}

// ---------------------------------------------------------------------------
// Hierarchy: get-or-create product type / product / engagement / test

async function ensureProductType(): Promise<Id> {
  const existing = (await listAll<{ id: Id }>(`/product_types/?name=${encodeURIComponent(PRODUCT_TYPE)}`))[0]
  if (existing) return existing.id
  if (DRY_RUN) {
    log(`[dry-run] would create product type "${PRODUCT_TYPE}"`)
    return -1
  }
  const created = await api<{ id: Id }>(`/product_types/`, { method: 'POST', json: { name: PRODUCT_TYPE } })
  log(`created product type "${PRODUCT_TYPE}"`)
  return created.id
}

async function ensureProduct(cid: string, name: string, ptId: Id, map: DojoMap): Promise<Id> {
  if (map.product[cid]) return map.product[cid]
  const tagged = (await listAll<DojoProduct>(`/products/?tag=${encodeURIComponent(TAG(cid))}`))[0]
  if (tagged) {
    map.product[cid] = tagged.id
    return tagged.id
  }
  if (DRY_RUN) {
    log(`[dry-run] would create product "${name}" (${TAG(cid)})`)
    return -1
  }
  const created = await api<DojoProduct>(`/products/`, {
    method: 'POST',
    json: { name, description: `Aegis project ${cid} — auto-synced findings from ${SITE}`, prod_type: ptId, tags: [TAG(cid)] },
  })
  map.product[cid] = created.id
  return created.id
}

async function ensureEngagement(productId: Id, cid: string, map: DojoMap): Promise<Id> {
  if (map.engagement[cid]) return map.engagement[cid]
  if (productId < 0) {
    log(`[dry-run] would create engagement "${ENGAGEMENT_NAME}" on ${cid}`)
    return -1
  }
  const existing = (await listAll<DojoEngagement>(`/engagements/?product=${productId}&name=${encodeURIComponent(ENGAGEMENT_NAME)}`))[0]
  if (existing) {
    map.engagement[cid] = existing.id
    return existing.id
  }
  if (DRY_RUN) {
    log(`[dry-run] would create engagement "${ENGAGEMENT_NAME}" on ${cid}`)
    return -1
  }
  const created = await api<DojoEngagement>(`/engagements/`, {
    method: 'POST',
    json: { name: ENGAGEMENT_NAME, product: productId, target_start: '2020-01-01', target_end: '2099-12-31', status: 'In Progress', engagement_type: 'CI/CD' },
  })
  map.engagement[cid] = created.id
  return created.id
}

async function ensureEnvironment(): Promise<void> {
  // no `name` filter on this endpoint — match client-side (the list is tiny)
  const existing = (await listAll<{ id: Id; name: string }>(`/development_environments/`)).find((e) => e.name === 'aegis')
  if (existing) return
  if (DRY_RUN) {
    log('[dry-run] would create development environment "aegis"')
    return
  }
  await api(`/development_environments/`, { method: 'POST', json: { name: 'aegis' } })
  log('created development environment "aegis"')
}

async function findTest(engagementId: Id, repoId: string, map: DojoMap): Promise<Id | null> {
  if (engagementId < 0) return null
  const key = `${engagementId}|${repoId}`
  if (map.test[key]) return map.test[key]
  const existing = (await listAll<DojoTest>(`/tests/?engagement=${engagementId}&title=${encodeURIComponent(repoId)}`))[0]
  if (existing) {
    map.test[key] = existing.id
    return existing.id
  }
  return null
}

function scanForm(body: Record<string, string | Blob>, doc: object, filename: string): FormData {
  const form = new FormData()
  for (const [k, v] of Object.entries(body)) form.append(k, v)
  form.append('file', new Blob([JSON.stringify(doc)], { type: 'application/json' }), filename)
  return form
}

// ---------------------------------------------------------------------------
// push

async function push(snap: Snapshot) {
  const vulnAliases = new Map(snap.vulns.map((v) => [v.id, v.aliases]))
  const map = await loadMap()
  const ptId = await ensureProductType()
  await ensureEnvironment()

  const projects = snap.projects.filter((p) => !ONLY_PROJECTS || ONLY_PROJECTS.has(p.canonical_id))
  // Repos to push: every repo with findings, plus repos whose test already exists
  // (so close_old_findings can mitigate advisories that disappeared).
  const pushedKeys = new Set(Object.keys(map.test))
  let pushed = 0
  let capped = false

  for (const p of projects) {
    const byRepo = new Map<string, Finding[]>()
    for (const f of p.findings) {
      if (f.status !== 'open') continue
      const list = byRepo.get(f.repo_id) ?? []
      list.push(f)
      byRepo.set(f.repo_id, list)
    }
    // include repos that had a test before but now carry no findings
    for (const r of p.repos) {
      if (!byRepo.has(r.canonical_id) && [...pushedKeys].some((k) => k.endsWith(`|${r.canonical_id}`))) byRepo.set(r.canonical_id, [])
    }
    if (!byRepo.size) continue

    const pid = await ensureProduct(p.canonical_id, p.display_name, ptId, map)
    const eid = await ensureEngagement(pid, p.canonical_id, map)
    if (!DRY_RUN && (pid < 0 || eid < 0)) continue

    await pool([...byRepo], 4, async ([repoId, findings]) => {
      if (pushed >= LIMIT) {
        capped = true
        return
      }
      const testId = await findTest(eid, repoId, map)
      const doc = { findings: findings.map((f) => toGeneric(f, vulnAliases, snap.summary.generated_at)) }
      const base = { scan_type: SCAN_TYPE, test_title: repoId, environment: 'aegis', close_old_findings: 'true', active: 'true', verified: 'false' }
      if (DRY_RUN) {
        log(`[dry-run] ${testId ? 'reimport' : 'import'} → ${repoId} (${findings.length} findings)`)
      } else if (testId) {
        await api(`/reimport-scan/`, { method: 'POST', form: scanForm({ ...base, test: String(testId) }, doc, `${repoId.split('/').pop()}.json`) })
      } else {
        await api(`/import-scan/`, { method: 'POST', form: scanForm({ ...base, engagement: String(eid) }, doc, `${repoId.split('/').pop()}.json`) })
      }
      pushed++
    })
    await saveMap(map)
    if (capped) break
  }
  log(`push: ${pushed} repo scans synced${capped ? ` (capped at DOJO_LIMIT)` : ''}`)
}

// ---------------------------------------------------------------------------
// pull — annotate dojo_status / sla_days_remaining onto snapshot findings

const statusOf = (f: DojoFinding): DojoStatus =>
  f.is_mitigated ? 'mitigated' : f.false_p ? 'false_positive' : f.risk_accepted ? 'risk_accepted' : f.out_of_scope ? 'out_of_scope' : f.duplicate ? 'duplicate' : f.verified ? 'verified' : 'new'

async function pull(snap: Snapshot) {
  const map = await loadMap()
  const productIds = Object.values(map.product)
  if (!productIds.length) {
    log('pull: no synced products in dojo-map — run `dojo push` first')
    return
  }
  const states = new Map<string, { status: DojoStatus; sla: number | null }>()
  for (const pid of productIds) {
    const findings = await listAll<DojoFinding>(`/findings/?test__engagement__product=${pid}&limit=1000`)
    for (const f of findings) {
      if (f.unique_id_from_tool) states.set(f.unique_id_from_tool, { status: statusOf(f), sla: f.sla_days_remaining ?? null })
    }
  }
  log(`pull: ${states.size} Dojo findings across ${productIds.length} products`)

  const now = Date.now()
  let annotated = 0
  for (const p of snap.projects) {
    for (const f of p.findings) {
      const st = states.get(f.id)
      if (st) {
        if (f.dojo_status !== st.status || f.sla_days_remaining !== st.sla) annotated++
        f.dojo_status = st.status
        f.sla_days_remaining = st.sla
      } else {
        // not pushed / removed in Dojo — clear stale triage state
        f.dojo_status = null
        f.sla_days_remaining = null
      }
    }
  }
  snap.summary.actionable_findings = recountActionable(snap.projects, now)
  await writeFile(OUT, JSON.stringify(snap))
  log(`pull: ${annotated} findings updated · ${snap.summary.actionable_findings} need action — wrote ${OUT}`)
}

// ---------------------------------------------------------------------------

async function main() {
  const cmd = process.argv[2]
  if (!['push', 'pull'].includes(cmd ?? '')) {
    console.error('usage: dojo.ts <push|pull>   (env: DOJO_URL, DOJO_API_KEY, DOJO_PRODUCT_TYPE, DOJO_DRY_RUN, DOJO_LIMIT, DOJO_PROJECTS)')
    process.exit(2)
  }
  if (!DOJO_URL || !DOJO_KEY) {
    log('DOJO_URL and DOJO_API_KEY are required — see deploy/dojo/README.md')
    process.exit(2)
  }
  const snap = JSON.parse(await readFile(OUT, 'utf8')) as Snapshot
  if (cmd === 'push') await push(snap)
  else await pull(snap)
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
