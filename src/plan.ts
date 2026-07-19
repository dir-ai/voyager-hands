/** A finding to remediate — shaped to accept voyager-net/browser findings directly
 *  (kind + target + optional caller-supplied params for values the hands must not
 *  guess). */
export interface Finding {
  kind: string
  target: string
  detail?: string
  /** Values only the operator can safely provide (SPF senders, CA name, rua). */
  params?: Record<string, string>
}

/** A proposed remediation. `ready` = the hands can build a valid action now; when
 *  false, `note` says exactly what the operator must supply — the hands NEVER
 *  fabricate mail-affecting content (SPF senders) or a CA. */
export interface Proposal {
  kind: string
  target: string
  params: Record<string, string>
  ready: boolean
  note: string
}

/** Plan conservative, reversible remediations for a finding. Safe defaults only
 *  (DMARC p=none is monitoring-only, zero mail impact); anything that could break
 *  delivery or trust is proposed but left NOT-ready until the operator fills it. */
export function plan(finding: Finding): Proposal[] {
  const t = finding.target
  const p = finding.params ?? {}
  switch (finding.kind) {
    case 'missing-dmarc':
      return [{
        kind: 'dns.record.add',
        target: t,
        params: { type: 'TXT', name: '_dmarc', value: `v=DMARC1; p=none;${p.rua ? ` rua=mailto:${p.rua};` : ''}` },
        ready: true,
        note: 'monitoring-only DMARC (p=none) — safe, zero mail impact; move to p=quarantine later',
      }]
    case 'missing-caa':
      return [{
        kind: 'dns.record.add',
        target: t,
        params: { type: 'CAA', name: '@', value: p.ca ? `0 issue "${p.ca}"` : '' },
        ready: Boolean(p.ca),
        note: p.ca ? `pin issuance to ${p.ca}` : 'supply your CA (e.g. letsencrypt.org) — the hands will not guess it',
      }]
    case 'missing-spf':
      return [{
        kind: 'dns.record.add',
        target: t,
        params: { type: 'TXT', name: '@', value: p.spf ?? '' },
        ready: Boolean(p.spf),
        note: 'SPF depends on YOUR mail senders — supply the record; the hands never guess senders (a wrong SPF silently drops mail)',
      }]
    default:
      return []
  }
}
