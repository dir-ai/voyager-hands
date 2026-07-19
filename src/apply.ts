import { attest } from './attest.js'
import { blastToTier, consentGate, requiresHuman } from './consent.js'
import type { Action, ApplyResult, Consent, Preview, Provider } from './types.js'

export interface ApplyOptions {
  /** The injected, least-privilege provider. WITHOUT it, nothing can mutate. */
  provider?: Provider
  /** The explicit consent decision. Consent from anywhere else is invalid. */
  consent?: Consent
  /** Must be true to mutate. DEFAULT false → dry-run/preview only (fail-safe). */
  execute?: boolean
  /** Re-sense after apply to confirm the fix held; return false to trigger
   *  auto-rollback. Default: "did the state actually change?". */
  verify?: (action: Action, provider: Provider) => Promise<boolean | null>
  now?: number
  onLog?: (line: string) => void
}

/** Compute the preview WITHOUT touching anything: blast radius, the consent it
 *  demands, a before→after diff, and any hard blockers. */
export async function preview(action: Action, provider?: Provider): Promise<Preview> {
  const consentTier = blastToTier(action.blastClass)
  const blockers: string[] = []
  if (!action.reversible) blockers.push('action has no inverse (irreversible) — refused; needs a runbook/two-person path, not the hands')
  let before: string | null = null
  if (provider) {
    try {
      before = await provider.read(action.target)
    } catch {
      before = null
    }
  }
  const diff = `before: ${before ?? '(unknown / no provider)'}\nproposed: ${action.summary}`
  return { action, blastClass: action.blastClass, consentTier, requiresHuman: requiresHuman(consentTier), diff, reversible: action.reversible, blockers }
}

/**
 * The hands pipeline: preview → hard consent gate → apply (windowed, rollback
 * armed) → verify (auto-rollback on regression) → attest. FAIL-SAFE at every
 * turn: no `execute` → dry-run; no provider → cannot mutate; consent insufficient
 * for the blast tier → withheld; irreversible → refused. The hands NEVER run
 * free-form commands and NEVER act without an explicit, tier-appropriate consent.
 */
export async function apply(action: Action, opts: ApplyOptions = {}): Promise<ApplyResult> {
  const now = opts.now ?? Date.now()
  const log = opts.onLog ?? (() => {})
  const prev = await preview(action, opts.provider)

  // Hard blockers (irreversible) → never applied.
  if (prev.blockers.length) {
    return withheld(action, now, prev.blockers, opts.consent?.by ?? null)
  }

  // Default = dry-run: preview only, nothing mutated.
  if (opts.execute !== true) {
    const before = opts.provider ? await safeRead(opts.provider, action.target) : null
    return {
      status: 'previewed',
      action,
      attestation: attest(action, 'previewed', before, null, null, now),
      rolledBack: false,
      verification: null,
      notes: [`DRY-RUN (execute!=true). ${prev.diff}`, `consent required: ${prev.consentTier}${prev.requiresHuman ? ' (human)' : ''}`],
    }
  }

  // From here, mutation is intended — every gate must pass.
  if (!opts.provider) {
    return withheld(action, now, ['no provider injected — the hands hold no credentials and cannot mutate on their own'], opts.consent?.by ?? null)
  }
  const gate = consentGate(prev.consentTier, opts.consent)
  if (gate) {
    return withheld(action, now, [gate, `blast ${action.blastClass} → ${prev.consentTier}`], opts.consent?.by ?? null)
  }

  const before = await safeRead(opts.provider, action.target)
  log(`applying: ${action.summary}`)
  try {
    await opts.provider.apply(action)
  } catch (e) {
    return {
      status: 'failed',
      action,
      attestation: attest(action, 'failed', before, before, opts.consent!.by, now),
      rolledBack: false,
      verification: null,
      notes: [`apply threw — no change committed`],
      error: e instanceof Error ? e.message : String(e),
    }
  }
  const after = await safeRead(opts.provider, action.target)

  // Verify (re-sense). Auto-rollback if it regressed.
  const passed = opts.verify ? await safeVerify(opts.verify, action, opts.provider) : after !== before ? true : null
  if (passed === false) {
    log('verification failed → auto-rolling back')
    let rolledBack = false
    if (action.inverse) {
      try {
        await opts.provider.apply({ ...action.inverse, inverse: undefined } as Action)
        rolledBack = true
      } catch {
        rolledBack = false
      }
    }
    const rolledState = await safeRead(opts.provider, action.target)
    return {
      status: rolledBack ? 'rolled-back' : 'failed',
      action,
      attestation: attest(action, rolledBack ? 'rolled-back' : 'failed', before, rolledState, opts.consent!.by, now),
      rolledBack,
      verification: { passed: false, method: opts.verify ? 'caller re-sense' : 'state-change check' },
      notes: rolledBack ? ['verification failed; auto-rolled back to the prior state'] : ['verification failed AND rollback failed — manual intervention required'],
    }
  }

  return {
    status: 'applied',
    action,
    attestation: attest(action, 'applied', before, after, opts.consent!.by, now),
    rolledBack: false,
    verification: { passed, method: opts.verify ? 'caller re-sense' : 'state-change check' },
    notes: [`applied by ${opts.consent!.by}${opts.consent!.secondBy ? ` + ${opts.consent!.secondBy}` : ''}`],
  }
}

function withheld(action: Action, now: number, notes: string[], by: string | null): ApplyResult {
  return { status: 'withheld', action, attestation: attest(action, 'withheld', null, null, by, now), rolledBack: false, verification: null, notes }
}
async function safeRead(p: Provider, target: string): Promise<string | null> {
  try {
    return await p.read(target)
  } catch {
    return null
  }
}
async function safeVerify(fn: NonNullable<ApplyOptions['verify']>, action: Action, p: Provider): Promise<boolean | null> {
  try {
    return await fn(action, p)
  } catch {
    return false
  }
}
