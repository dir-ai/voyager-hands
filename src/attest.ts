import type { Action, ActionStatus, Attestation } from './types.js'

/** A deterministic content hash (FNV-1a → base36) — no deps, reproducible. v0.1's
 *  "signature". A real cryptographic signature (in-toto/SLSA) is the future; the
 *  SHAPE (a tamper-evident receipt over exactly what changed) is here now. */
function hash(s: string): string {
  let h = 0x811c9dc5
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i)
    h = Math.imul(h, 0x01000193)
  }
  return (h >>> 0).toString(36)
}

/** Build the attestation receipt over the action + before/after state + consent +
 *  time — the audit trail that makes an action reversible and accountable. */
export function attest(action: Action, status: ActionStatus, before: string | null, after: string | null, consentBy: string | null, now: number): Attestation {
  const body = JSON.stringify({ kind: action.kind, target: action.target, params: action.params, status, before, after, consentBy, at: now })
  return {
    receipt: `att-${hash(body)}`,
    kind: action.kind,
    target: action.target,
    status,
    before,
    after,
    consentBy,
    at: now,
    inverseAvailable: Boolean(action.inverse),
  }
}
