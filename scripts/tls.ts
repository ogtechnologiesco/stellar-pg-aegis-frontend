// TLS certificate probe for project websites (snapshot builder only — node:tls).
// Connects to the DoH-resolved address with SNI rather than the system resolver's
// answer, so results reflect the real site's certificate even on networks that
// intercept DNS (sinkholes, captive portals, filtering appliances).

import tls from 'node:tls'
import type { TlsCheck } from '../src/api/types.ts'
import { dohQuery } from '../src/lib/doh.ts'

/**
 * Handshakes `name:443` and reports certificate validity. `valid` = chains to a
 * trusted CA for `name`; `invalid` = handshake completed but auth failed
 * (`error` carries the OpenSSL reason: UNABLE_TO_VERIFY_LEAF_SIGNATURE,
 * CERT_HAS_EXPIRED, ERR_TLS_CERT_ALTNAME_INVALID, ...); `unreachable` = could
 * not establish TLS at all.
 */
export async function tlsCheck(name: string, resolver?: string): Promise<TlsCheck> {
  const a = await dohQuery(name, 'A', { resolver })
  const ip = (a?.Answer ?? []).find((x) => x.type === 1)?.data ?? name
  return new Promise((resolve) => {
    const done = (r: TlsCheck) => {
      sock.destroy()
      resolve(r)
    }
    const sock = tls.connect({ host: ip, port: 443, servername: name, rejectUnauthorized: false, timeout: 10_000 })
    sock.once('secureConnect', () => {
      const cert = sock.getPeerCertificate()
      done({
        status: sock.authorized ? 'valid' : 'invalid',
        error: sock.authorized ? null : String(sock.authorizationError ?? 'certificate not trusted'),
        cert_expires_at: cert?.valid_to ?? null,
      })
    })
    sock.once('error', (e) => done({ status: 'unreachable', error: String((e as NodeJS.ErrnoException).code ?? e), cert_expires_at: null }))
    sock.once('timeout', () => done({ status: 'unreachable', error: 'timeout', cert_expires_at: null }))
  })
}
