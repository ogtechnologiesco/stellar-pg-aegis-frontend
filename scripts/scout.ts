// Scout (CoinFabrik) Soroban contract-lint pass: detects contract repos via a
// `soroban-sdk` manifest reference, runs `cargo scout-audit` under Scout's pinned
// detector nightly, and returns findings for the shared sast_findings list
// (tool:'scout'). Results are cached per commit SHA + tool version (30d).
//
// TRUST: scout COMPILES the target — dependency build.rs executes. Default runner
// is the coinfabrik/scout container on x86_64 hosts (env passthrough blocked);
// on arm64 hosts the amd64 image's detector-helper build crashes under emulation,
// so the local `cargo-scout-audit` binary runs with a secrets-stripped env.
//
// UPSTREAM BIT-ROT workaround: scout 0.3.17 pins dylint 4.1.2, whose driver build
// clones rust-lang/rust-clippy and revparses `master` — deleted when clippy moved
// into rust-lang/rust and the repo switched to a JOSH-filtered history (which also
// broke the first-parent revwalk). A local bare mirror whose `master` points at a
// pre-JOSH commit on the old first-parent chain restores both. git's url.insteadOf
// IS honored by dylint_internal's clone_with_cli (`git clone` subprocess). The
// built driver caches in ~/.dylint_drivers — the mirror is only needed on cold
// builds, but every docker run is cold (fresh container).
import { execFile } from 'node:child_process'
import { cp, mkdir, readdir, readFile, rm, stat, writeFile } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import { promisify } from 'node:util'
import type { SastFinding, SastSeverity } from '../src/api/types.ts'
import { CACHE_DIR, cacheGet, cacheSet, log } from './cache.ts'
import { ensureClone, GOVC_TTL_MS } from './govulncheck.ts'
import type { SastContext } from './semgrep.ts'

const execP = promisify(execFile)

/** cargo-scout-audit version — must match a published coinfabrik/scout image tag. */
export const SCOUT_VERSION = process.env.SCOUT_VERSION ?? '0.3.17'
export const SCOUT_MAX = Number(process.env.SCOUT_MAX_REPOS ?? 0) || Infinity
/** Comma-separated owner/name filter — restrict analysis to specific repos. */
export const SCOUT_REPOS = process.env.SCOUT_REPOS?.split(',').map((s) => s.trim().toLowerCase()).filter(Boolean)
/** docker | local | auto (default auto: docker on x86_64, local elsewhere). */
const SCOUT_RUNNER = process.env.SCOUT_RUNNER ?? 'auto'
/** Per-repo analysis budget — contract dep trees compile under the lint toolchain. */
const SCOUT_TIMEOUT = Number(process.env.SCOUT_TIMEOUT ?? 0) || 900_000
const PER_REPO_CAP = 100
/** Standalone contract manifests outside a workspace get one -m run each, capped. */
const MAX_CONTRACT_RUNS = 3
/** Pre-JOSH clippy commit on the old first-parent chain (nightly-2025-10-31 bump).
 * Its first-parent history still contains every per-nightly toolchain bump the
 * revwalk looks for, incl. nightly-2025-09-18. */
const CLIPPY_MASTER_SHA = 'c71f7b63f8fb3d7f0b2b0e26d0e029646f93fb9e'
const CLIPPY_MIRROR_DIR = resolve(CACHE_DIR, 'clippy-mirror')
const SCOUT_GITCONFIG = resolve(CACHE_DIR, 'scout-gitconfig')
const SCRATCH_DIR = resolve(CACHE_DIR, 'scout-src')

interface Runner {
  kind: 'docker' | 'local'
  /** docker: image ref; local: binary path */
  ref: string
}

async function sh(cmd: string, args: string[], cwd: string, timeout = 120_000, env?: Record<string, string>): Promise<{ out: string; err: string; ok: boolean }> {
  try {
    const { stdout, stderr } = await execP(cmd, args, { cwd, timeout, maxBuffer: 128 * 1024 * 1024, env: { ...process.env, ...env } })
    return { out: String(stdout), err: String(stderr), ok: true }
  } catch (e) {
    const x = e as { stdout?: string | Buffer; stderr?: string | Buffer }
    return { out: String(x.stdout ?? ''), err: String(x.stderr ?? e), ok: false }
  }
}

/** Like sh() but the given env REPLACES process.env entirely — used for the local
 * runner so secrets can't leak into build.rs executions. */
async function shIsolated(cmd: string, args: string[], cwd: string, timeout: number, env: Record<string, string>): Promise<{ out: string; err: string; ok: boolean }> {
  try {
    const { stdout, stderr } = await execP(cmd, args, { cwd, timeout, maxBuffer: 128 * 1024 * 1024, env })
    return { out: String(stdout), err: String(stderr), ok: true }
  } catch (e) {
    const x = e as { stdout?: string | Buffer; stderr?: string | Buffer }
    return { out: String(x.stdout ?? ''), err: String(x.stderr ?? e), ok: false }
  }
}

/** Child env for the local runner — keeps only what rustup/cargo/git need; no
 * secrets or tokens leak into the build (dependency build.rs executes). */
function sanitizedEnv(extra: Record<string, string>): Record<string, string> {
  const keep = ['PATH', 'HOME', 'TMPDIR', 'USER', 'LOGNAME', 'LANG', 'LC_ALL', 'TERM', 'CARGO_HOME', 'RUSTUP_HOME', 'SSL_CERT_FILE', 'SYSTEMROOT', 'WINDIR']
  const env: Record<string, string> = {}
  for (const k of keep) if (process.env[k]) env[k] = process.env[k]!
  return { ...env, ...extra }
}

let runner: Runner | null | undefined
/** Pick the runner. docker requires a working daemon AND an x86_64 host (the image
 * is amd64-only; on arm64 its dylint build crashes under Rosetta). local requires
 * cargo + either an installed cargo-scout-audit or a successful --locked install. */
export async function scoutRunner(): Promise<Runner | null> {
  if (runner !== undefined) return runner
  if (SCOUT_RUNNER !== 'local') {
    const docker = await sh('docker', ['info', '--format', '{{.ServerVersion}}'], '.', 30_000)
    const onX64 = process.arch === 'x64'
    if (docker.ok && (onX64 || SCOUT_RUNNER === 'docker')) {
      const img = `coinfabrik/scout:${SCOUT_VERSION}`
      // amd64-only image — explicit platform so forced-docker works on arm64 too.
      return (runner = { kind: 'docker', ref: img })
    }
  }
  if (SCOUT_RUNNER === 'docker') return (runner = null)
  if (!(await sh('cargo', ['--version'], '.')).ok) return (runner = null)
  if ((await sh('which', ['cargo-scout-audit'], '.')).ok) return (runner = { kind: 'local', ref: 'cargo' })
  const bin = `${process.env.CARGO_HOME ?? `${process.env.HOME}/.cargo`}/bin/cargo-scout-audit`
  if (await stat(bin).then(() => true, () => false)) return (runner = { kind: 'local', ref: 'cargo' })
  log(`cargo-scout-audit not found — running \`cargo install cargo-scout-audit@${SCOUT_VERSION} --locked\` (~15min)`)
  if ((await sh('cargo', ['install', `cargo-scout-audit@${SCOUT_VERSION}`, '--locked'], '.', 1_800_000)).ok) return (runner = { kind: 'local', ref: 'cargo' })
  return (runner = null)
}

/** Bare mirror of rust-lang/rust-clippy whose `master` is pinned to the last
 * pre-JOSH toolchain-bump commit — restores dylint 4.1.2's deleted `master` ref
 * AND the first-parent revwalk the post-JOSH history broke. ~15MB full bare
 * clone (shallow clones break — JOSH-filtered history has phantom parents). */
async function ensureClippyMirror(): Promise<string | null> {
  if (await stat(join(CLIPPY_MIRROR_DIR, 'HEAD')).then(() => true, () => false)) return CLIPPY_MIRROR_DIR
  log('scout: cloning rust-clippy mirror (needed for cold driver builds)')
  if (!(await sh('git', ['clone', '--bare', 'https://github.com/rust-lang/rust-clippy', CLIPPY_MIRROR_DIR], CACHE_DIR, 600_000)).ok) return null
  if (!(await sh('git', ['-C', CLIPPY_MIRROR_DIR, 'branch', '-f', 'master', CLIPPY_MASTER_SHA], '.')).ok) return null
  return CLIPPY_MIRROR_DIR
}

/** gitconfig that rewrites the clippy clone URL to the local mirror. Written under
 * .cache and referenced via GIT_CONFIG_GLOBAL (local runner) — the user's own
 * git config is never touched. In docker the container's own config is used. */
async function ensureScoutGitconfig(mirror: string): Promise<string> {
  await mkdir(CACHE_DIR, { recursive: true })
  await writeFile(SCOUT_GITCONFIG, `[url "file://${mirror}"]\n\tinsteadOf = https://github.com/rust-lang/rust-clippy\n`)
  return SCOUT_GITCONFIG
}

interface ContractCandidate {
  /** directories containing a contract Cargo.toml (repo-relative, '' = root) */
  dirs: string[]
  /** Cargo.lock mentions soroban-sdk even if no manifest does (e.g. examples) */
  lockMentionsSdk: boolean
}

/** A repo is a contract candidate when any Cargo.toml references `soroban-sdk`
 * or its Cargo.lock does. Manifests carry the primary signal; the lockfile is a
 * fallback for repos that build contracts outside manifest deps. */
async function detectContracts(dir: string, depth = 0): Promise<ContractCandidate> {
  const cand: ContractCandidate = { dirs: [], lockMentionsSdk: false }
  if (depth > 6) return cand
  const ents = await readdir(dir, { withFileTypes: true }).catch(() => null)
  if (!ents) return cand
  for (const e of ents) {
    if (e.isDirectory()) {
      if (e.name === 'target' || e.name === 'node_modules' || e.name.startsWith('.')) continue
      const sub = await detectContracts(join(dir, e.name), depth + 1)
      cand.dirs.push(...sub.dirs.map((d) => join(e.name, d)))
      cand.lockMentionsSdk ||= sub.lockMentionsSdk
    } else if (e.name === 'Cargo.toml') {
      const body = await readFile(join(dir, e.name), 'utf8').catch(() => '')
      if (/\bsoroban-sdk\b/.test(body)) cand.dirs.push(depth === 0 ? '' : '.')
    } else if (e.name === 'Cargo.lock') {
      const body = await readFile(join(dir, e.name), 'utf8').catch(() => '')
      if (/\bname = "soroban-sdk"/.test(body)) cand.lockMentionsSdk = true
    }
  }
  return cand
}

// ---- scout output schema (verified against coinfabrik/scout:0.3.17) ----
interface ScoutReport {
  categories?: { vulnerabilities?: { id?: string; severity?: string; short_message?: string; help?: string }[] }[]
  findings?: {
    vulnerability_id?: string
    error_message?: string
    span?: string // "file.rs:line:col - line:col"
    code_snippet?: string
    file_path?: string
  }[]
}

/** Scout severities folded onto the three-bucket SastSeverity scale. */
const SCOUT_SEV: Record<string, SastSeverity> = { critical: 'error', high: 'error', medium: 'warning', minor: 'info', enhancement: 'info', informational: 'info' }
const SEV_ORDER: Record<SastSeverity, number> = { error: 0, warning: 1, info: 2 }
const trim = (s: string | undefined, n: number) => (s ? s.replace(/\s+$/, '').slice(0, n) : null)
// span looks like "lib.rs:16:9 - 16:9" or "contracts/foo/src/lib.rs:4:5 - 4:10"
const SPAN_RE = /:(\d+):(\d+)\s*-\s*(\d+):(\d+)\s*$/

function parseScout(out: string, ctx: SastContext, sha: string): SastFinding[] | null {
  let report: ScoutReport
  try {
    report = JSON.parse(out)
  } catch {
    return null
  }
  if (!Array.isArray(report.findings)) return []
  // detector id → native severity (Critical/Medium/Minor/Enhancement)
  const sevById = new Map<string, string>()
  for (const c of report.categories ?? []) for (const v of c.vulnerabilities ?? []) if (v.id && v.severity) sevById.set(v.id, v.severity)
  const seen = new Set<string>()
  const findings: SastFinding[] = []
  for (const f of report.findings) {
    if (!f.vulnerability_id || !f.file_path) continue
    const m = SPAN_RE.exec(f.span ?? '')
    const raw = sevById.get(f.vulnerability_id) ?? /^\[(\w+)\]/.exec(f.error_message ?? '')?.[1] ?? 'info'
    const severity = SCOUT_SEV[raw.toLowerCase()] ?? 'info'
    const fp = `${f.file_path}:${m?.[1] ?? 0}:${m?.[2] ?? 0}`
    if (seen.has(`${f.vulnerability_id}|${fp}`)) continue
    seen.add(`${f.vulnerability_id}|${fp}`)
    findings.push({
      id: `${ctx.repo_id}|${f.vulnerability_id}|${fp}`,
      ...ctx,
      rule_id: f.vulnerability_id,
      message: trim((f.error_message ?? '').replace(/^\[\w+\]\s*/, ''), 400) ?? f.vulnerability_id,
      severity,
      tool: 'scout',
      raw_severity: raw,
      path: f.file_path,
      start_line: Number(m?.[1] ?? 0),
      end_line: Number(m?.[3] ?? m?.[1] ?? 0),
      snippet: trim(f.code_snippet, 500),
      commit_sha: sha,
      cwe: [],
      owasp: [],
    })
  }
  findings.sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity] || a.rule_id.localeCompare(b.rule_id))
  return findings
}

/** The project's own rust-toolchain pins break detector compilation (rustup picks
 * the pin for scout's internal builds), so the scan runs on a scratch copy with
 * pins neutralized — the shared clone pool is never mutated. */
async function scratchCopy(dir: string, key: string): Promise<string | null> {
  const scratch = resolve(SCRATCH_DIR, `${key.replace('/', '__')}-${process.pid}`)
  await rm(scratch, { recursive: true, force: true })
  await mkdir(SCRATCH_DIR, { recursive: true })
  await cp(dir, scratch, { recursive: true }).catch(() => null)
  await rm(join(scratch, '.git'), { recursive: true, force: true })
  // neutralize rust-toolchain pins anywhere in the tree
  const strip = async (d: string, depth = 0): Promise<void> => {
    if (depth > 6) return
    for (const e of await readdir(d, { withFileTypes: true }).catch(() => [])) {
      if (e.isDirectory()) {
        if (e.name === 'target' || e.name === 'node_modules' || e.name.startsWith('.')) continue
        await strip(join(d, e.name), depth + 1)
      } else if (e.name === 'rust-toolchain' || e.name === 'rust-toolchain.toml' || e.name === 'rust-toolchain.yaml') {
        await rm(join(d, e.name), { force: true })
      }
    }
  }
  await strip(scratch)
  return scratch
}

/** Clone (or refresh) the repo, detect contracts, run scout, return findings.
 * null = could not analyze (clone/build/analysis failed). `{contract:false}` for
 * non-contract repos (cheap cached skip). */
export async function scoutRepo(r: Runner, gh: { owner: string; name: string }, url: string, ctx: SastContext): Promise<{ sha: string; contract: boolean; findings: SastFinding[] } | null> {
  const key = `${gh.owner}/${gh.name}`.toLowerCase()
  const clone = await ensureClone(gh, url)
  if (!clone) {
    log(`scout: clone failed for ${key}`)
    return null
  }
  const { dir, sha } = clone
  const ck = `scout1:${SCOUT_VERSION}:${key}@${sha}`
  const hit = await cacheGet<{ contract: boolean; findings: SastFinding[] } | null>(ck, GOVC_TTL_MS)
  if (hit !== undefined) return hit ? { sha, contract: hit.contract, findings: hit.findings } : null

  const mirror = await ensureClippyMirror()
  const scratch = await scratchCopy(dir, key)
  if (!scratch) return null
  try {
    const cand = await detectContracts(scratch)
    if (!cand.dirs.length && !cand.lockMentionsSdk) {
      await cacheSet(ck, { contract: false, findings: [] })
      return { sha, contract: false, findings: [] }
    }
    // Where to point scout: the root manifest when the root IS a contract or a
    // workspace (workspace runs cover contract members); otherwise each
    // standalone contract manifest gets its own -m run, capped.
    const rootManifest = await readFile(join(scratch, 'Cargo.toml'), 'utf8').catch(() => '')
    const runDirs =
      /\bsoroban-sdk\b/.test(rootManifest) || /^\s*\[workspace\]/m.test(rootManifest) || !cand.dirs.length
        ? ['']
        : cand.dirs.slice(0, MAX_CONTRACT_RUNS)
    const cfg = r.kind === 'local' && mirror ? await ensureScoutGitconfig(mirror) : null
    const findings: SastFinding[] = []
    let analyzed = 0
    for (const dir of runDirs) {
      const outFile = `scout-${process.pid}-${analyzed}.json`
      const manifestArg = dir ? `-m /src/${dir}/Cargo.toml` : ''
      let run: { out: string; err: string; ok: boolean }
      if (r.kind === 'docker') {
        const outDir = resolve(scratch, '.scout-out')
        await mkdir(outDir, { recursive: true })
        const platform = process.arch === 'x64' ? [] : ['--platform', 'linux/amd64']
        const cmd = [
          'run', '--rm', ...platform,
          '-e', 'INPUT_TARGET=/src',
          '-e', `INPUT_SCOUT_ARGS=-o json --output-path /out/${outFile}${manifestArg ? ` ${manifestArg}` : ''}`,
          '-v', `${scratch}:/src`,
          '-v', `${outDir}:/out`,
          ...(mirror ? ['-v', `${mirror}:/clippy:ro`] : []),
          '--entrypoint', 'bash',
          r.ref,
          '-c',
          `git config --global url."file:///clippy".insteadOf "https://github.com/rust-lang/rust-clippy" 2>/dev/null; /usr/local/bin/entrypoint.sh`,
        ]
        run = await sh('docker', cmd, scratch, SCOUT_TIMEOUT)
        const raw = await readFile(join(outDir, outFile), 'utf8').catch(() => '')
        run = { ...run, out: raw || run.out }
      } else {
        const env = sanitizedEnv({ ...(cfg ? { GIT_CONFIG_GLOBAL: cfg } : {}), CARGO_TERM_COLOR: 'never' })
        const args = ['scout-audit', '-o', 'json', '--output-path', outFile]
        if (dir) args.push('-m', join(dir, 'Cargo.toml'))
        run = await shIsolated('cargo', args, scratch, SCOUT_TIMEOUT, env)
        const raw = await readFile(join(scratch, outFile), 'utf8').catch(() => '')
        run = { ...run, out: raw || run.out }
      }
      const parsed = run.out ? parseScout(run.out, ctx, sha) : null
      if (parsed === null) {
        const tail = run.err.trim().split('\n').filter((l) => l.includes('ERROR') || l.includes('error')).pop()?.slice(0, 160) || run.err.trim().split('\n').pop()?.slice(0, 160)
        log(`scout failed in ${key}${dir ? ` (${dir})` : ''} — ${tail}`)
        continue
      }
      analyzed++
      findings.push(...parsed)
    }
    if (!analyzed) {
      await cacheSet(ck, null)
      return null
    }
    const capped = findings.sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity] || a.rule_id.localeCompare(b.rule_id)).slice(0, PER_REPO_CAP)
    await cacheSet(ck, { contract: true, findings: capped })
    return { sha, contract: true, findings: capped }
  } finally {
    await rm(scratch, { recursive: true, force: true }).catch(() => {})
  }
}
