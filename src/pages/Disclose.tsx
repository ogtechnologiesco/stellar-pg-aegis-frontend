import { useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router'
import { Ban, Clock, Lock, Search, ShieldCheck, ShieldOff } from 'lucide-react'
import { useDisclosureLookup, useProjects } from '../api'
import { DisclosureChannels } from '../components/DisclosureCard'
import { Card, EmptyState, ErrorState, PageHeader, Skeleton, StatusPill } from '../components/ui'

function useDebounced<T>(value: T, ms = 250) {
  const [v, setV] = useState(value)
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms)
    return () => clearTimeout(t)
  }, [value, ms])
  return v
}

const GUIDANCE = [
  { icon: Lock, title: 'Report privately', text: 'Use the recommended channel. Never open a public issue, PR or Discord thread with vulnerability details.' },
  { icon: ShieldCheck, title: 'Include a minimal reproduction', text: 'Affected version, impact, proof-of-concept and suggested fix. Encrypt if the policy provides a PGP key.' },
  { icon: Clock, title: 'Allow time to patch', text: 'Coordinate a disclosure date with the maintainer. 90 days is a common default.' },
  { icon: Ban, title: 'Do not test on mainnet', text: 'Reproduce on testnet or a local network. Do not access other users’ funds or data.' },
]

export default function Disclose() {
  const [params, setParams] = useSearchParams()
  const [query, setQuery] = useState(params.get('q') ?? '')
  const debounced = useDebounced(query)
  const { data, error, isFetching } = useDisclosureLookup(debounced)
  const gaps = useProjects({ disclosure_gap: true, wg_listed: true, sort: 'criticality', limit: 10 })

  useEffect(() => {
    setParams(
      (p) => {
        if (debounced) p.set('q', debounced)
        else p.delete('q')
        return p
      },
      { replace: true },
    )
  }, [debounced, setParams])

  return (
    <>
      <PageHeader eyebrow="Disclosure routing" title="Report a vulnerability" description="Find the right private channel for reporting to any Stellar public good. Aegis does not accept vulnerability reports itself; it points you to the maintainers." />

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="space-y-4 lg:col-span-2">
          <div className="relative">
            <Search className="pointer-events-none absolute top-1/2 left-4 size-5 -translate-y-1/2 text-slate-500" />
            <input autoFocus value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Project or repository, e.g. py-stellar-base" className="input h-14 rounded-2xl pl-12 text-base" aria-label="Project or repository" />
          </div>

          {error ? (
            <ErrorState error={error} />
          ) : !debounced ? (
            <>
              <Card>
                <EmptyState icon={<Search className="size-5" />} title="Search for a project" description="Results show SECURITY.md contacts, GitHub private vulnerability reporting, security.txt and bounty programs, ranked by preference." />
              </Card>
              {(gaps.data?.total ?? 0) > 0 && (
                <Card className="p-5">
                  <h2 className="mb-1 flex items-center gap-2 text-sm font-semibold text-slate-100">
                    <ShieldOff className="size-4 text-amber-300" /> Coverage gaps — {gaps.data!.total} public good{gaps.data!.total === 1 ? '' : 's'} without a private channel
                  </h2>
                  <p className="mb-3 text-xs leading-relaxed text-slate-500">
                    No PVR, SECURITY.md contact or security.txt was found. These are standards-adoption targets for the WG — enabling PVR or publishing a policy is the fix.
                  </p>
                  <ul className="space-y-1">
                    {gaps.data!.items.map((p) => (
                      <li key={p.canonical_id}>
                        <Link to={`/projects/${p.canonical_id}`} className="flex items-center justify-between rounded-lg px-2 py-1.5 text-sm text-slate-300 transition hover:bg-white/[0.03] hover:text-white">
                          <span>{p.display_name}</span>
                          <span className="text-xs text-slate-600">{p.category ?? '—'}</span>
                        </Link>
                      </li>
                    ))}
                  </ul>
                </Card>
              )}
            </>
          ) : isFetching && !data ? (
            <Skeleton className="h-40 rounded-2xl" />
          ) : !data?.length ? (
            <Card>
              <EmptyState title="No matching project" description="Only SCF public goods tracked by PG Atlas are listed." />
            </Card>
          ) : (
            data.map(({ project, channels }) => (
              <Card key={project.canonical_id} className="p-5">
                <div className="mb-4 flex flex-wrap items-center gap-3">
                  <Link to={`/projects/${project.canonical_id}`} className="text-base font-semibold text-white hover:text-indigo-200">
                    {project.display_name}
                  </Link>
                  <StatusPill status={project.activity_status} />
                  <span className="text-xs text-slate-500">{project.category}</span>
                </div>
                <DisclosureChannels channels={channels} />
              </Card>
            ))
          )}
        </div>

        <Card className="h-fit p-5">
          <h2 className="mb-4 text-sm font-semibold text-slate-100">Responsible disclosure checklist</h2>
          <ul className="space-y-4">
            {GUIDANCE.map(({ icon: Icon, title, text }) => (
              <li key={title} className="flex gap-3">
                <div className="grid size-8 shrink-0 place-items-center rounded-lg bg-indigo-500/10 text-indigo-300">
                  <Icon className="size-4" />
                </div>
                <div>
                  <div className="text-sm font-medium text-slate-200">{title}</div>
                  <p className="mt-0.5 text-xs leading-relaxed text-slate-400">{text}</p>
                </div>
              </li>
            ))}
          </ul>
        </Card>
      </div>
    </>
  )
}
