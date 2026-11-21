# Stellar PG Aegis

Security posture, vulnerability exposure and disclosure routing for Stellar public goods.
See `Specification.md` for the full product/technical spec.

## Layout

- `Specification.md` — product + technical specification (source of truth for API contract, FR numbers).
- `frontend/` — React 19 + TypeScript + Vite 6 + Tailwind CSS v4 dashboard.
- Backend — not yet implemented (planned: FastAPI + PostgreSQL, see spec §8).

## Frontend

Run from `frontend/`:

- Install: `npm install`
- Dev server: `npm run dev` (http://localhost:5173)
- Lint: `npm run lint`
- Typecheck + production build: `npm run build`
- Data snapshot: `GITHUB_TOKEN=$(gh auth token) PG_ATLAS_API=<url> npm run data:refresh`

Verification before finishing a change: `npm run lint && npm run build`.

### Data layer

- `src/api/types.ts` — response types mirroring spec FR10. Keep in sync with `Specification.md`.
  `null` always means "not collected" — never fabricate values. `criticality_score` is an
  integer count of dependents, `adoption_score` is 0–100 (both PG Atlas semantics).
- `src/api/client.ts` — `AegisApi` interface + HTTP client (`/v1/*`) for the future backend.
- `src/api/snapshotClient.ts` — serves `public/data/snapshot.json`.
- `src/api/index.ts` — `VITE_API_BASE_URL` set → live HTTP client; otherwise the snapshot.
- `scripts/build-snapshot.ts` — snapshot builder; run `npm run data:refresh`.
  Sources: PG Atlas API (`PG_ATLAS_API`, default `https://api.pgatlas.xyz`), OSV `/v1/querybatch`
  + `/v1/vulns`, CISA KEV, FIRST EPSS, GitHub GraphQL/REST (`GITHUB_TOKEN`), OpenSSF Scorecard,
  security.txt, and DNS/TLS (`DOH_API`, default `https://dns.google/resolve`) —
  the DoH pass sets `dnssec_status` (valid / unsigned / broken via the AD bit plus a
  SERVFAIL→cd retry) and `has_caa` (label-climbing CAA lookup) on each non-GitHub
  project website, plus `tls` (validity, error, cert expiry) from a `:443` handshake
  at the DoH-resolved IP via `scripts/tls.ts` — connecting by IP keeps results honest
  on networks that intercept DNS. Respects PG Atlas 100 req/min limit, honors `Retry-After`, and disk-caches
  in `scripts/.cache/` (PG responses 24h, GitHub/Scorecard 72h) so refreshes resume.
  `GH_MAX_REPOS=<n>` caps GitHub enrichment per run (repos with findings first, then by stars);
  unenriched repos show as "unknown" in the UI.
  govulncheck call analysis (Go repos with findings, most findings first): shallow-clones into
  `scripts/.cache/clones/`, runs `govulncheck -json ./...` per `go.mod`, and annotates each
  finding `reachability` (called / not-called / unflagged; `null` = not analyzed). Verdicts are
  cached per commit SHA for 30d. Needs `go` + `govulncheck` (auto-`go install`s when `go` is
  present). `GOVC=0` disables; `GOVC_MAX_REPOS=<n>` caps cloned repos; `GOVC_REPOS=owner/name,...`
  restricts to specific repos. Shared helpers live in `scripts/cache.ts` and
  `scripts/govulncheck.ts`; PG Atlas cache keys normalize to the canonical host so
  `PG_ATLAS_API` mirrors reuse them.
  Semgrep SAST (WG-listed repos, highest criticality first): reuses the same clone pool,
  runs `semgrep scan --config p/security-audit --json` per repo, and writes a separate
  `sast_findings` array on each project — no priority score; severity is Semgrep's own
  `error`/`warning`/`info`, not CVSS. Results are cached per commit SHA + semgrep
  version + ruleset name for 30d (`null` = could not scan); `summary.sast` records
  ruleset/tool_version/coverage (`null` = never ran). Needs `python3` + `pip`
  (auto-`pip install --user`s when absent; pin via `SEMGREP_VERSION`, default 1.184.0).
  `SEMGREP=0` disables; `SEMGREP_MAX_REPOS=<n>` caps cloned repos;
  `SEMGREP_REPOS=owner/name,...` restricts; `SEMGREP_CONFIG` overrides the ruleset.
  `p/*` registry rules drift upstream — expect occasional diffs that aren't code changes.
  Scout (CoinFabrik `cargo-scout-audit`, Soroban contract lint): same WG target selection
  and clone pool; a repo is analyzed only when a `Cargo.toml`/`Cargo.lock` references
  `soroban-sdk` (non-contract repos are cheap cached skips). Findings join `sast_findings`
  tagged `tool:'scout'` — `severity` folds Scout's Critical/Medium/Minor/Enhancement onto
  error/warning/info with the original kept in `raw_severity`. Cached per commit SHA +
  `SCOUT_VERSION` (default 0.3.17) for 30d; `summary.scout` mirrors `summary.sast`.
  Runner: `coinfabrik/scout` container on x86_64 hosts, local `cargo-scout-audit`
  elsewhere — the amd64 image's detector-helper crashes under Rosetta on arm64.
  `SCOUT=0` disables; `SCOUT_MAX_REPOS`/`SCOUT_REPOS` mirror the Semgrep knobs;
  `SCOUT_RUNNER` forces docker|local. TRUST: scout compiles the repo — dependency
  `build.rs` executes — docker runs with no env passthrough; local runs use a
  secrets-stripped child env (`shIsolated`). Scans happen on a scratch copy with
  `rust-toolchain*` pins neutralized (a project pin breaks detector compilation —
  scout always compiles under its own detector nightly anyway). Workaround inside:
  scout's pinned dylint 4.1.2 clones rust-clippy and revparses the deleted `master`
  branch — `ensureClippyMirror()` keeps a ~15MB bare mirror in `.cache/` with
  `master` pinned to a pre-JOSH commit whose first-parent chain still contains the
  nightly toolchain bumps; `url.insteadOf` (honored by dylint's `git clone`
  subprocess, NOT by libgit2 remotes) redirects the fetch via `GIT_CONFIG_GLOBAL`
  (local) or container `git config` (docker). Driver builds cache in
  `~/.dylint_drivers` — the mirror only matters on cold builds. Known coverage
  limit: the detector toolchain is rustc 1.92-nightly — workspaces whose deps
  require ≥1.93 (e.g. soroban-cli 28-era tooling) fail analysis → `null`.
- `scripts/annotate-reachability.ts` — `npm run data:reachability`: runs the same govulncheck
  pass against the existing `public/data/snapshot.json` without a full refresh.
- `scripts/annotate-sast.ts` — `npm run data:sast`: runs the same Semgrep pass against
  the existing `public/data/snapshot.json` without a full refresh. Preserves `tool:'scout'`
  findings when rewriting `sast_findings`.
- `scripts/annotate-scout.ts` — `npm run data:scout`: runs the same Scout pass against
  the existing `public/data/snapshot.json` without a full refresh. Preserves non-scout
  findings when rewriting `sast_findings`.
- `scripts/dojo.ts` — `npm run data:dojo-push` / `data:dojo-pull`: syncs findings with the
  WG's DefectDojo OSS triage+SLA backend (see `deploy/dojo/README.md`). Push creates
  Product-per-project / Engagement `aegis-scan` / Test-per-repo and reimport-scans Generic
  findings (dedup on `unique_id_from_tool` = finding id — requires
  `DD_DEDUPLICATION_ALGORITHM_PER_PARSER` on the instance). Pull writes `dojo_status` +
  `sla_days_remaining` onto findings then calls `recountActionable` — cleared triage states
  (`false_positive`, `risk_accepted`, `out_of_scope`, `mitigated`, `duplicate`) drop the
  actionable flag. Needs `DOJO_URL` + `DOJO_API_KEY`; `DOJO_DRY_RUN=1`, `DOJO_LIMIT`,
  `DOJO_PROJECTS` for partial runs. Skipped entirely when unset.
- `scripts/diff-snapshot.ts` — `npm run data:diff <old.json> <new.json>`: markdown report of
  new/resolved findings, KEV adds, reachability flips and SAST deltas; appends `new_findings=`,
  `sast_new=` etc. to `$GITHUB_OUTPUT`. Used by the snapshot-refresh workflow.
- Stellar Security Portal (`SECURITY_PORTAL_API`, default `https://stellarsecurityportal.com/api/v1`):
  `GET /protocols` + `POST /reports {}`; only `approved` reports are used. Protocol→project
  mapping is curated (`PORTAL_MAP` in `build-snapshot.ts`, same shape as `WG_MAP`) plus a
  `protocol.url` repo/website-host match; unmatched protocols are logged. Per-report page:
  `/report/{id}`. Empty `audits`/`audit_reports_count` = checked, none found; `null` = portal
  unreachable.

### GitHub Actions

- `.github/workflows/snapshot-refresh.yml` — nightly + dispatch: `data:refresh` + `data:review`,
  diffs against the previous snapshot into the job summary, commits `snapshot.json` back.
  `GH_MAX_REPOS=800` bounds GitHub enrichment, `SEMGREP_MAX_REPOS=40` bounds Semgrep
  SAST scans and `SCOUT_MAX_REPOS=40` bounds Scout contract scans; set
  `AEGIS_GH_TOKEN` (PAT) if the default `GITHUB_TOKEN` rate-limits or
  branch protection blocks the push (falls back to an artifact).
- `.github/workflows/aegis-scan.yml` — `workflow_call` reusable scan for any repo: wraps
  `google/osv-scanner-action` (PR-diff variant on PRs, full scan otherwise) + govulncheck per
  `go.mod` + Semgrep SAST (`semgrep-config` input, default `p/security-audit`), merged SARIF
  uploads to code scanning. `rust-reach` input (default `false`) adds EXPERIMENTAL
  Rust reachability via `reachsec` (github.com/xizheyin/reachsec @548b228b, pinned) +
  `callgraph4rs` on nightly-2025-08-09: builds a MIR call graph of the workspace and
  reports real call chains into advisory-affected functions. Statuses: `reachable`
  (call chain found → also exit 1), `not_reachable` (no chain found — tool itself
  labels this "potentially vulnerable", NOT proof of safety; it over-approximates),
  `analysis_failed`, `no_metadata` (advisory lacks `affects.functions` — most
  RustSec advisories). Runs `cargo build` → dependency build.rs executes — keep
  opt-in for untrusted sources. Verified on stellar-registry/cli (31 advisories,
  0 errors, minutes not hours; project `rust-toolchain.toml` pin is overridden by
  `+nightly`). Replaces an earlier osv-scanner `--call-analysis=rust` attempt whose
  DWARF/LTO approach was ELF-only and produced systematic false negatives.
  `scout` input (default `false`) adds CoinFabrik Soroban contract lint via the
  `coinfabrik/scout` container — only fires when a `soroban-sdk` manifest exists,
  compiles under a pinned detector nightly (`build.rs` executes → keep opt-in),
  uploads native SARIF under the `scout` category, and warns-but-exits-clean on
  tool failure.
- `.github/workflows/vuln-scan.yml` — dogfoods `aegis-scan.yml` on this repo (PRs + weekly).
  Advisory ignores live in `osv-scanner.toml` at repo root.
- React Query hooks (`useProjects`, `useVulnExposure`, ...) live in `src/api/index.ts`.
- `src/lib/doh.ts` — shared DoH client (`dnssecStatus`, `caaRecords`) used by both the
  snapshot builder and the `/dns` page (dns.google sends CORS headers, so the page runs
  the same checks live in the browser; override via `VITE_DOH_API`).
- Priority weights (spec FR5) live in `src/lib/priority.ts`; severity falls back to the
  advisory label when no CVSS v3 score is computable (`unknown` severity is possible).
- The **needs-action gate** (`isActionable` in `src/lib/priority.ts`, spec FR5b) replaces raw
  CVE counts as the project flag: a finding is actionable only with exploit/applicability
  evidence (KEV, `reachability: 'called'`, EPSS ≥ 0.2 on a fixable issue), a fix unpatched
  >90d, or a critical >14d. Cleared reachability (`not-called`/`unflagged`), `inferred`
  confidence and non-vulnerability kinds (unmaintained/notice/…) never flag. Findings carry
  `actionable`; projects carry `actionable_findings` + `oldest_actionable_age_days`;
  `summary.actionable_findings` is the ecosystem total. `scripts/actionable.ts`
  (`recountActionable`) recomputes all of it inside the annotate/review recounts — call it
  whenever a pass mutates findings so the flag never goes stale.

### Conventions

- Tailwind v4 with custom utilities (`card`, `input`, `btn-primary`, `btn-ghost`, `th`, `td`) defined via `@utility` in `src/index.css`.
- Shared UI primitives in `src/components/ui.tsx`; pages are lazy-loaded in `src/App.tsx`.
- Recharts animations are disabled (`isAnimationActive={false}`) so charts render reliably (incl. headless screenshots).
- In `useEffect`, never implicitly return the result of `window.scrollTo(...)` — Chrome returns a Promise, which React treats as an invalid cleanup.

### Known audit note

`npm audit` reports a moderate `minimatch` advisory (GHSA-g3hv-75wg-m249) via `typescript-eslint` (dev-only, lint tooling).
The fix requires minimatch 11.x, which `typescript-eslint` does not yet accept; revisit when it updates.
