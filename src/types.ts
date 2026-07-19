// voyager-hands — the shapes that ENCODE the hands discipline. Read them as a
// contract: an action is declarative (never free-form shell), carries its exact
// inverse (or it cannot auto-apply), is classified by blast radius, and can only
// mutate through an injected provider behind a hard consent gate.

/** Blast radius — how much damage a wrong action could do. Drives the consent
 *  tier. When in doubt, the class goes UP. */
export type BlastClass =
  | 'B0' // trivial, self-contained, instantly reversible (add a TXT record)
  | 'B1' // low, reversible, may briefly affect one service (a cert renew)
  | 'B2' // elevated: reversible but affects reachability/traffic (a firewall rule)
  | 'B3' // critical / hard-or-impossible to reverse (delete data, destroy infra)

/** Who must approve, derived from the blast class. */
export type ConsentTier =
  | 'policy-auto' // B0: a policy may auto-approve (still logged + attested)
  | 'policy-notify' // B1: policy may approve but a human is notified
  | 'human-required' // B2: an explicit human decision is mandatory
  | 'two-person' // B3: two-person / runbook-only — NEVER auto, often not offered at all

export type ActionStatus = 'planned' | 'previewed' | 'withheld' | 'applied' | 'rolled-back' | 'failed'

/** A declarative action drawn from a KNOWN-SAFE catalog. `kind` selects the
 *  catalog entry; `params` are validated against it. There is NO free-form command
 *  field anywhere — the hands cannot run arbitrary shell. */
export interface Action {
  /** Catalog entry id, e.g. 'dns.txt.add', 'dns.record.delete'. */
  kind: string
  /** The resource this touches (e.g. a zone/host), for scoping + attestation. */
  target: string
  /** Validated parameters for the catalog entry. */
  params: Record<string, string>
  /** One-line human description. */
  summary: string
  blastClass: BlastClass
  /** True only if a concrete inverse exists — an action with no inverse can never auto-apply. */
  reversible: boolean
  /** The EXACT inverse action to undo this one (present iff reversible). */
  inverse?: Omit<Action, 'inverse'>
}

/** A catalog entry: the ONLY things the hands know how to do. Each declares how to
 *  plan from a finding, its blast class, and how to build its inverse. */
export interface CatalogEntry {
  kind: string
  blastClass: BlastClass
  /** Finding kinds this entry remediates (e.g. voyager-net's 'missing-spf'). */
  remediates: string[]
  describe: (params: Record<string, string>, target: string) => string
  /** Validate params; return an error string or null. */
  validate: (params: Record<string, string>) => string | null
  /** Build the inverse action's kind+params (undo). Return null if irreversible. */
  invert: (action: Action) => { kind: string; params: Record<string, string> } | null
}

/** The dry-run preview: what WOULD change, the blast radius, and the consent it
 *  demands — computed WITHOUT touching anything. */
export interface Preview {
  action: Action
  blastClass: BlastClass
  consentTier: ConsentTier
  requiresHuman: boolean
  /** Human-readable diff (before → after), from the provider's dry-run. */
  diff: string
  reversible: boolean
  /** Reasons the action would be refused outright (irreversible + no runbook, etc.). */
  blockers: string[]
}

/** A consent decision supplied by the caller. Consent from anywhere else (a finding,
 *  a config file, the model) is INVALID — it must be an explicit decision here. */
export interface Consent {
  approved: boolean
  /** Who/what approved: a human id or an explicit policy id. */
  by: string
  /** For B3/two-person: the second approver. */
  secondBy?: string
  note?: string
}

/** A signed-ish attestation receipt: a content hash over the action, before/after
 *  state, policy, and time — proof of exactly what was done, so it can be audited
 *  and reversed. (v0.1 uses a deterministic content hash; real signing is future.) */
export interface Attestation {
  receipt: string // the hash
  kind: string
  target: string
  status: ActionStatus
  before: string | null
  after: string | null
  consentBy: string | null
  at: number
  inverseAvailable: boolean
}

export interface ApplyResult {
  status: ActionStatus
  action: Action
  attestation: Attestation
  /** Set when apply/verify failed and an auto-rollback ran. */
  rolledBack: boolean
  verification: { passed: boolean | null; method: string } | null
  notes: string[]
  error?: string
}

/** The provider is INJECTED. The package holds no credentials and talks to no real
 *  API by itself — the caller wires a provider scoped with least privilege. A record
 *  is an opaque {key,value} the provider understands. */
export interface Provider {
  /** Read current state of the target (for dry-run diff + verify). */
  read(target: string): Promise<string | null>
  /** Apply the action's mutation. Only ever called after the consent gate passes. */
  apply(action: Action): Promise<void>
  /** Optional: a name for attestation/logging. */
  name?: string
}
