// Copy-ready templates for the standard disclosure documents Aegis measures —
// GitHub PVR setup, SECURITY.md and RFC 9116 security.txt. Shown on a project's
// "Security practices" card when the corresponding signal is missing.

const hostOf = (website: string | null) => {
  try {
    return website ? new URL(/^https?:\/\//i.test(website) ? website : `https://${website}`).host : 'example.org'
  } catch {
    return 'example.org'
  }
}

/** RFC 9116 security.txt — required fields are Contact and Expires. */
export function securityTxtTemplate(website: string | null): string {
  const host = hostOf(website)
  const expires = new Date(Date.now() + 366 * 86_400_000).toISOString()
  return [
    '# Stellar public good — security contact (RFC 9116)',
    '# Publish at https://' + host + '/.well-known/security.txt',
    '# Replace the contact with your preferred private channel',
    '# (e.g. the GitHub private vulnerability reporting URL below).',
    `Contact: mailto:security@${host}`,
    `Expires: ${expires}`,
    `Canonical: https://${host}/.well-known/security.txt`,
    'Preferred-Languages: en',
  ].join('\n')
}

export function securityMdTemplate(displayName: string, website: string | null): string {
  return `# Security Policy

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues, pull requests, or Discord.**

Report vulnerabilities in ${displayName} privately through one of these channels:

- **GitHub private vulnerability reporting** — open the repository's *Security* tab
  and click *Report a vulnerability*. (Enable it in the repo under
  *Settings → Code security and analysis → Private vulnerability reporting*.)
- **Email** — security@[your-domain]. Include the affected version, impact, a
  minimal reproduction and, if possible, a suggested fix.
${website ? `- **security.txt** — see ${website.replace(/\/$/, '')}/.well-known/security.txt for current contact details.` : ''}

We aim to acknowledge reports within 72 hours and will coordinate a disclosure
date with you once a fix is ready.

## Scope

This policy covers the repositories listed in this project's GitHub
organization. Do not test against mainnet or other users' funds — reproduce on
testnet or a local network.

## Supported Versions

| Version | Supported |
| ------- | --------- |
| latest  | ✅        |
| older   | ❌        |
`
}

export const PVR_DOCS_URL = 'https://docs.github.com/en/code-security/security-advisories/working-with-repository-security-advisories/configuring-private-vulnerability-reporting-for-a-repository'
