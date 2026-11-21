# DefectDojo — internal triage + SLA backend

Aegis syncs its snapshot findings into a self-hosted **DefectDojo OSS** instance that the
Working Group uses for triage (verified / false positive / risk accepted / mitigated) and
severity SLA tracking. Dojo stays internal — only triage decisions and SLA countdowns flow
back onto the public dashboard via `dojo pull`.

> **SBOM note:** SBOM *inventory* (Dependency Locations, `/api/v2/sbom-import/`, VEX export)
> is DefectDojo **Pro**-only and out of scope — Aegis's SBOM source of truth remains the
> PG Atlas SPDX submissions. For component-level tracking, an OWASP Dependency-Track
> instance can be added later (Dojo OSS has a `dependency_track` parser).

## Deploy (WG server / cloud VM)

1. Clone the upstream repo (do not vendor it here):

   ```bash
   git clone https://github.com/DefectDojo/django-DefectDojo
   cd django-DefectDojo
   ```

2. Configure `docker-compose.override.yml` (or `dojo/settings/.env.prod` per upstream docs).
   Required overrides for Aegis dedup + TLS behind the WG reverse proxy:

   ```yaml
   services:
     uwsgi:
       environment:
         # Aegis findings dedup on unique_id_from_tool (= Aegis finding id
         # "VULN|repo|dep") so reimports match across snapshot refreshes.
         DD_DEDUPLICATION_ALGORITHM_PER_PARSER: '{"Generic Findings Import": "unique_id_from_tool_or_hash_code"}'
         DD_HASHCODE_FIELDS_PER_SCANNER: '{"Generic Findings Import": ["unique_id_from_tool"]}'
         DD_ALLOWED_HOSTS: 'dojo.<wg-domain>'
         DD_CSRF_TRUSTED_ORIGINS: 'https://dojo.<wg-domain>'
         DD_SITE_URL: 'https://dojo.<wg-domain>'
   ```

3. `docker compose up -d` — ~6 containers (django/uwsgi, celeryworker, celerybeat,
   postgres, rabbitmq, nginx). Upstream install docs:
   https://docs.defectdojo.com/en/running_instance/upgrading/

4. Create an API token: admin UI → API v2 Key → token for the sync account, or

   ```bash
   docker compose exec uwsgi ./manage.py drf_create_token <user>
   ```

5. SLA configuration (per-Asset, by severity): Configuration → SLA Configurations.
   Suggested values, aligned with Aegis's grace windows:

   | Severity | Days |
   |---|---|
   | Critical | 14 |
   | High | 30 |
   | Medium | 90 |
   | Low | 180 |

   Apply the config to the Aegis products (it becomes the default for new ones).

6. Backup: nightly `pg_dump` of the `defectdojo` database.

## Sync from this repo

```bash
export DOJO_URL=https://dojo.<wg-domain>
export DOJO_API_KEY=<token>

npm run data:dojo-push    # create hierarchy + reimport-scan per repo
npm run data:dojo-pull    # pull triage status + SLA back into snapshot.json
```

Env knobs: `DOJO_DRY_RUN=1` (print the plan, write nothing), `DOJO_LIMIT=<n>`,
`DOJO_PROJECTS=<id,id,…>`, `DOJO_PRODUCT_TYPE` (default `Stellar Public Goods`).

Data mapping (`scripts/dojo.ts`): Product = Aegis project (tagged
`aegis:<canonical_id>`) → ongoing Engagement `aegis-scan` → Test per repo
(`close_old_findings` stays per-repo). Findings carry `unique_id_from_tool`,
`vuln_id_from_tool`, component/purl, EPSS, KEV, fix version, and Aegis tags
(`confidence:*`, `src:*`, `reach:*`, `kind:*`, `aegis:actionable`).

Pull-back semantics: `false_positive`, `risk_accepted`, `out_of_scope`,
`mitigated`, `duplicate` clear the finding's needs-action flag; `sla_days_remaining`
is shown as an `SLA ±Nd` badge.

GitHub Actions: set secrets `DOJO_URL` + `DOJO_API_KEY` — `snapshot-refresh.yml`
runs the sync automatically after `data:refresh`/`data:review` and skips cleanly
when unset.

## Verified against a live instance (spike notes)

- **Dedup works** with the env config above: reimporting the same findings creates
  zero duplicates (`unique_id_from_tool` honored).
- **`close_old_findings` is scoped per Test** — a reimport mitigates only findings
  missing from *that repo's* file, never other repos/products. It also closes
  **triaged** findings (a risk-accepted finding omitted from the file was
  mitigated), and a finding that reappears later is reactivated **without** its
  prior triage state (`risk_accepted` lost). Never push partial/empty scan files:
  `dojo.ts` always sends the repo's full open-finding set, and the snapshot-diff
  step in CI is the guard against a bad snapshot mass-closing triaged work.
- **SLA counts from the finding `date`** (Aegis sends the advisory publish date),
  not the import date — countdowns reflect remediation latency since disclosure.
  SLA configurations cover Critical/High/Medium/Low only; `Info` (Aegis `unknown`)
  findings get `sla_days_remaining = null`.
- **`environment` must exist** — `dojo.ts` auto-creates a Development Environment
  named `aegis` (the API rejects unknown environment names).
- `/development_environments/` has **no `name` filter** — lookups must match
  client-side (other endpoints filter `name`/`title`/`tag`/`product` normally).
- Triage via API: `risk_accepted` is a **Risk Acceptance workflow object**
  (`POST /risk_acceptance/` with `accepted_findings`), not a direct PATCH on the
  finding; `false_p`, `out_of_scope`, `is_mitigated`, `verified` are PATCH-able.
