import { useEffect, useState, type FormEvent } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useSearchParams } from 'react-router'
import { AlertTriangle, Globe, Radar, Search, ShieldCheck } from 'lucide-react'
import { caaRecords, DEFAULT_RESOLVER, dnssecStatus, dohQuery } from '../lib/doh'
import type { DnssecStatus } from '../api/types'
import { Card, EmptyState, ErrorState, PageHeader, Pill, Skeleton } from '../components/ui'

const RESOLVER = import.meta.env.VITE_DOH_API || DEFAULT_RESOLVER

/** URL or bare domain → hostname (URL parsing handles lowercase + punycode). */
function toHost(raw: string): string | null {
  const s = raw.trim().toLowerCase()
  if (!s) return null
  try {
    const h = new URL(s.includes('://') ? s : `https://${s}`).hostname.replace(/\.$/, '')
    const labels = h.split('.')
    return labels.length >= 2 && /[a-z]/.test(labels[labels.length - 1]) ? h : null
  } catch {
    return null
  }
}

/** no-cors fetch — resolves only if TCP+TLS+HTTP all succeeded (redirects resolve
 * as opaqueredirect responses rather than being followed cross-origin). Browsers
 * hide the failure reason (cert error vs outage vs filtered DNS), so this is a boolean. */
async function httpsProbe(host: string): Promise<boolean> {
  try {
    await fetch(`https://${host}/`, { mode: 'no-cors', signal: AbortSignal.timeout(10_000) })
    return true
  } catch {
    return false
  }
}

async function check(host: string) {
  const [dns, caa, https, probe] = await Promise.all([dnssecStatus(host, RESOLVER), caaRecords(host, RESOLVER), httpsProbe(host), dohQuery(host, 'SOA', { resolver: RESOLVER })])
  if (!probe) throw new Error(`Could not reach the DNS resolver at ${RESOLVER}`)
  return { dns, caa, https }
}

const DNSSEC: Record<DnssecStatus, { tone: 'emerald' | 'slate' | 'amber'; label: string; desc: string }> = {
  valid: { tone: 'emerald', label: 'DNSSEC valid', desc: 'Responses are cryptographically signed and pass validation.' },
  unsigned: { tone: 'slate', label: 'DNSSEC unsigned', desc: 'The zone is not signed, so answers are not authenticated — common, but offers no protection against DNS spoofing.' },
  broken: { tone: 'amber', label: 'DNSSEC broken', desc: 'The zone is signed but fails validation. Validating resolvers refuse to resolve the domain — treat as an outage-level misconfiguration.' },
}

export default function DnsCheck() {
  const [params, setParams] = useSearchParams()
  const [input, setInput] = useState(params.get('q') ?? '')
  const [host, setHost] = useState(() => toHost(params.get('q') ?? ''))
  const [invalid, setInvalid] = useState(false)

  useEffect(() => {
    setParams(
      (p) => {
        if (host) p.set('q', host)
        else p.delete('q')
        return p
      },
      { replace: true },
    )
  }, [host, setParams])

  const { data, error, isFetching } = useQuery({ queryKey: ['domain-check', host], queryFn: () => check(host!), enabled: host != null })

  const submit = (e: FormEvent) => {
    e.preventDefault()
    const h = toHost(input)
    setInvalid(input.trim().length > 0 && h == null)
    setHost(h)
  }

  return (
    <>
      <PageHeader eyebrow="DNS security" title="Domain check" description="Live DNSSEC and CAA checks for any domain — the same signals Aegis tracks on project websites. Queries run in your browser via DNS-over-HTTPS; nothing is sent to Aegis." />

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="space-y-4 lg:col-span-2">
          <form onSubmit={submit} className="flex gap-2">
            <div className="relative flex-1">
              <Search className="pointer-events-none absolute top-1/2 left-4 size-5 -translate-y-1/2 text-slate-500" />
              <input autoFocus value={input} onChange={(e) => setInput(e.target.value)} placeholder="Domain or URL, e.g. stellar.org" className="input h-14 w-full rounded-2xl pl-12 text-base" aria-label="Domain or URL" />
            </div>
            <button type="submit" className="btn-primary h-14 rounded-2xl px-6">
              Check
            </button>
          </form>
          {invalid && <p className="text-xs text-amber-300">That does not look like a domain name — try a hostname like “stellar.org”.</p>}

          {!host ? (
            <Card>
              <EmptyState icon={<Globe className="size-5" />} title="Enter a domain to check" description="Reports whether DNSSEC validates and whether CAA records restrict certificate issuance." />
            </Card>
          ) : error ? (
            <Card>
              <ErrorState error={error} />
            </Card>
          ) : isFetching || !data ? (
            <Skeleton className="h-40 rounded-2xl" />
          ) : (
            <Card className="p-5">
              <div className="mb-4 flex flex-wrap items-center gap-3">
                <span className="font-mono text-base font-semibold text-white">{host}</span>
                {data.dns.status ? <Pill tone={DNSSEC[data.dns.status].tone}>{DNSSEC[data.dns.status].label}</Pill> : <Pill tone="slate">DNSSEC unknown</Pill>}
                {data.dns.nxdomain && <Pill tone="rose">name does not exist</Pill>}
              </div>

              <div className="space-y-5">
                <div className="flex gap-3">
                  <div className="grid size-8 shrink-0 place-items-center rounded-lg bg-indigo-500/10 text-indigo-300">
                    <ShieldCheck className="size-4" />
                  </div>
                  <div>
                    <div className="text-sm font-medium text-slate-200">DNSSEC</div>
                    <p className="mt-0.5 text-xs leading-relaxed text-slate-400">
                      {data.dns.status ? DNSSEC[data.dns.status].desc : 'Could not determine — the resolver gave no definitive answer.'}
                      {data.dns.nxdomain && ' The queried name does not exist (NXDOMAIN); the verdict reflects the zone, not a live record.'}
                    </p>
                  </div>
                </div>

                <div className="flex gap-3">
                  <div className="grid size-8 shrink-0 place-items-center rounded-lg bg-indigo-500/10 text-indigo-300">
                    {data.https ? <ShieldCheck className="size-4" /> : <AlertTriangle className="size-4" />}
                  </div>
                  <div className="min-w-0">
                    <div className="text-sm font-medium text-slate-200">HTTPS endpoint</div>
                    <p className="mt-0.5 text-xs leading-relaxed text-slate-400">
                      {data.https ? (
                        'TLS handshake and HTTP succeeded — the certificate is trusted by your device and resolver.'
                      ) : (
                        <>
                          Connection failed — browsers hide the reason (certificate error, outage, or a DNS/network filter intercepting the domain).{' '}
                          <a href={`https://${host}/`} target="_blank" rel="noreferrer" className="text-indigo-300 hover:text-indigo-200">
                            Open the site
                          </a>{' '}
                          to see the exact error.
                        </>
                      )}
                    </p>
                  </div>
                </div>

                <div className="flex gap-3">
                  <div className="grid size-8 shrink-0 place-items-center rounded-lg bg-indigo-500/10 text-indigo-300">
                    {data.caa.found === false ? <AlertTriangle className="size-4" /> : <Globe className="size-4" />}
                  </div>
                  <div className="min-w-0">
                    <div className="text-sm font-medium text-slate-200">CAA</div>
                    {data.caa.found == null ? (
                      <p className="mt-0.5 text-xs leading-relaxed text-slate-400">Could not determine.</p>
                    ) : data.caa.found ? (
                      <>
                        <p className="mt-0.5 text-xs leading-relaxed text-slate-400">
                          Only the listed certificate authorities may issue for this domain{data.caa.at !== host && <> — inherited from <span className="font-mono text-slate-300">{data.caa.at}</span></>}.
                        </p>
                        <ul className="mt-2 space-y-1">
                          {data.caa.records.map((r, k) => (
                            <li key={k} className="rounded-md bg-white/[0.03] px-2.5 py-1 font-mono text-[11px] break-all text-slate-300">
                              {r}
                            </li>
                          ))}
                        </ul>
                      </>
                    ) : (
                      <p className="mt-0.5 text-xs leading-relaxed text-slate-400">No CAA records — any public certificate authority may issue certificates for this domain.</p>
                    )}
                  </div>
                </div>
              </div>
            </Card>
          )}
        </div>

        <Card className="h-fit p-5">
          <h2 className="mb-4 flex items-center gap-2 text-sm font-semibold text-slate-100">
            <Radar className="size-4 text-indigo-300" /> What is checked
          </h2>
          <ul className="space-y-4 text-xs leading-relaxed text-slate-400">
            <li>
              <div className="text-sm font-medium text-slate-200">DNSSEC validation</div>
              An A-record lookup through a validating resolver: the <code className="text-slate-300">AD</code> flag marks authenticated answers; a SERVFAIL retried with validation off distinguishes <span className="text-amber-300">broken</span> from unreachable.
            </li>
            <li>
              <div className="text-sm font-medium text-slate-200">CAA policy</div>
              CAA records on the domain or its parents — the nearest ancestor’s policy constrains which certificate authorities may issue for the whole subtree.
            </li>
            <li>
              <div className="text-sm font-medium text-slate-200">HTTPS reachability</div>
              A live TLS+HTTP probe from your browser — this reflects <em>your</em> resolver and trust store, unlike the DNS checks. A failure while DNSSEC shows valid often means a network filter is intercepting the domain.
            </li>
            <li className="border-t border-white/[0.05] pt-3">
              Resolver: <span className="font-mono break-all text-slate-300">{RESOLVER}</span>
              <br />
              Results are single-vantage and uncached — project pages show the snapshot-time verdict instead.
            </li>
          </ul>
        </Card>
      </div>
    </>
  )
}
