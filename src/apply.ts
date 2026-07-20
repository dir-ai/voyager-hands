import { attest } from './attest.js'
import { blastToTier, consentGate, requiresHuman } from './consent.js'
import type { Action, ActionStatus, ApplyResult, Consent, Preview, Provider } from './types.js'

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
      mutated: false,
      verification: null,
      notes: [`DRY-RUN (execute!=true). ${prev.diff}`, `consent required: ${prev.consentTier}${prev.requiresHuman ? ' (human)' : ''}`],
    }
  }

  // From here, mutation is intended — every gate must pass.
  if (!opts.provider) {
    return withheld(action, now, ['no provider injected — the hands hold no credentials and cannot mutate on their own'], opts.consent?.by ?? null)
  }
  const gate = consentGate(prev.consentTier, opts.consent, action, now)
  if (gate) {
    return withheld(action, now, [gate, `blast ${action.blastClass} → ${prev.consentTier}`], opts.consent?.by ?? null)
  }

  const provider = opts.provider
  const before = await safeRead(provider, action.target)
  log(`applying: ${action.summary}`)
  let applyError: string | null = null
  try {
    await provider.apply(action)
  } catch (e) {
    applyError = e instanceof Error ? e.message : String(e)
  }

  // MANDATORY read-back — on BOTH paths. A provider can mutate and THEN throw; we
  // must observe the real state, never assume "threw ⇒ nothing changed".
  const afterAttempt = await safeRead(provider, action.target)
  const mutated = afterAttempt !== before

  if (applyError) {
    // The apply reported failure. If nothing actually changed, it's a clean failure.
    if (!mutated) {
      return result('failed', action, before, before, opts.consent!.by, now, false, false, null, [`apply failed and the target is unchanged (verified by read-back)`], applyError)
    }
    // It threw AFTER a partial mutation — the dangerous case Codex flagged. Try to
    // roll back to `before` and CONFIRM the restore by reading again.
    log('apply threw AFTER mutating the target → attempting rollback')
    const { rolledBack, restored } = await rollback(provider, action, before)
    return rolledBack
      ? result('rolled-back', action, before, restored, opts.consent!.by, now, true, false, { passed: false, method: 'read-back after partial mutation' }, ['apply threw after a PARTIAL mutation; rolled back and CONFIRMED the prior state was restored'], applyError)
      : result('failed', action, before, afterAttempt, opts.consent!.by, now, true, false, { passed: false, method: 'read-back after partial mutation' }, ['apply threw after a PARTIAL mutation and rollback did NOT restore the prior state — the target is in an INCONSISTENT state, manual intervention required'], applyError)
  }

  const after = afterAttempt
  // Verify (re-sense). Without a caller-supplied semantic verify, a mere
  // before≠after change is NOT proof the fix worked — report it unverified, never
  // as success. Auto-rollback only on a real verification FAILURE.
  const passed = opts.verify ? await safeVerify(opts.verify, action, provider) : null
  const method = opts.verify ? 'caller re-sense' : 'none — applied but NOT semantically verified'
  if (passed === false) {
    log('verification failed → auto-rolling back')
    const { rolledBack, restored } = await rollback(provider, action, before)
    return result(
      rolledBack ? 'rolled-back' : 'failed', action, before, restored, opts.consent!.by, now, !rolledBack, rolledBack,
      { passed: false, method },
      rolledBack ? ['verification failed; auto-rolled back and confirmed the prior state was restored'] : ['verification failed AND rollback did not restore the prior state — manual intervention required'],
    )
  }

  const notes = [`applied by ${opts.consent!.by}${opts.consent!.secondBy ? ` + ${opts.consent!.secondBy}` : ''}`]
  if (passed === null) notes.push('NOT verified — supply a `verify` re-sense to confirm the fix actually took effect; a state change alone is not proof')
  return result('applied', action, before, after, opts.consent!.by, now, mutated, false, { passed, method }, notes)
}

/** Roll back via the exact inverse, then CONFIRM by reading the state again — a
 *  rollback is only "done" if the target actually returned to `before`. */
async function rollback(provider: Provider, action: Action, before: string | null): Promise<{ rolledBack: boolean; restored: string | null }> {
  if (!action.inverse) return { rolledBack: false, restored: await safeRead(provider, action.target) }
  try {
    await provider.apply({ ...action.inverse, inverse: undefined } as Action)
  } catch {
    /* fall through to the confirming read */
  }
  const restored = await safeRead(provider, action.target)
  return { rolledBack: restored === before, restored }
}

function result(
  status: ActionStatus, action: Action, before: string | null, after: string | null, by: string | null, now: number,
  mutated: boolean, rolledBack: boolean, verification: ApplyResult['verification'], notes: string[], error?: string,
): ApplyResult {
  return { status, action, attestation: attest(action, status, before, after, by, now), rolledBack, mutated, verification, notes, error }
}

function withheld(action: Action, now: number, notes: string[], by: string | null): ApplyResult {
  return { status: 'withheld', action, attestation: attest(action, 'withheld', null, null, by, now), rolledBack: false, mutated: false, verification: null, notes }
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
