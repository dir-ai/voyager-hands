import type { Action, CatalogEntry } from './types.js'

/** The known-safe action catalog — the ONLY things the hands can do. The first
 *  slice is DNS records: reversible, zero-blast to add, and the natural pair for
 *  voyager-net's DNS hygiene findings (missing SPF/DMARC/CAA). No free-form command
 *  exists anywhere in this catalog by construction. */
export const CATALOG: CatalogEntry[] = [
  {
    kind: 'dns.record.add',
    blastClass: 'B0', // adding a record is instantly reversible (delete it)
    remediates: ['missing-dmarc', 'missing-caa', 'missing-spf', 'missing-mta-sts', 'missing-dkim'],
    describe: (p, target) => `add ${p.type} record "${p.name}" on ${target} → ${truncate(p.value, 80)}`,
    validate: (p) => {
      if (!p.type || !/^(TXT|CAA|MX|A|AAAA|CNAME)$/i.test(p.type)) return 'type must be one of TXT/CAA/MX/A/AAAA/CNAME'
      if (!p.name) return 'name (record name, "@" for apex) is required'
      if (!p.value || !p.value.trim()) return 'value is required — the hands do not guess record content (e.g. SPF senders); supply it for review'
      if (p.value.length > 2048) return 'value too long'
      return null
    },
    invert: (a) => ({ kind: 'dns.record.delete', params: { type: a.params.type, name: a.params.name, value: a.params.value } }),
  },
  {
    kind: 'dns.record.delete',
    blastClass: 'B1', // removing a record CAN break mail/validation — low but not trivial
    remediates: [],
    describe: (p, target) => `delete ${p.type} record "${p.name}" on ${target}`,
    validate: (p) => {
      if (!p.type) return 'type is required'
      if (!p.name) return 'name is required'
      return null
    },
    // Inverse is add-back — only reversible if we captured the value being removed.
    invert: (a) => (a.params.value ? { kind: 'dns.record.add', params: { type: a.params.type, name: a.params.name, value: a.params.value } } : null),
  },
]

export function entryFor(kind: string): CatalogEntry | undefined {
  return CATALOG.find((e) => e.kind === kind)
}

/** Assemble a validated Action (with its inverse) from a catalog kind + params.
 *  Throws a descriptive Error if the kind is unknown or params are invalid — the
 *  hands refuse to construct anything not in the catalog. */
export function buildAction(kind: string, target: string, params: Record<string, string>): Action {
  const entry = entryFor(kind)
  if (!entry) throw new Error(`unknown action kind "${kind}" — not in the known-safe catalog`)
  const err = entry.validate(params)
  if (err) throw new Error(`invalid params for ${kind}: ${err}`)
  const base: Action = {
    kind,
    target,
    params,
    summary: entry.describe(params, target),
    blastClass: entry.blastClass,
    reversible: false,
  }
  const inv = entry.invert(base)
  if (inv) {
    const invEntry = entryFor(inv.kind)
    base.reversible = true
    base.inverse = {
      kind: inv.kind,
      target,
      params: inv.params,
      summary: invEntry ? invEntry.describe(inv.params, target) : `undo ${kind}`,
      blastClass: invEntry?.blastClass ?? base.blastClass,
      reversible: true,
    }
  }
  return base
}

function truncate(s: string, n: number): string {
  return s.length > n ? s.slice(0, n) + '…' : s
}
