import { createHash } from 'node:crypto'
import type { Action, ActionStatus, Attestation } from './types.js'
import { actionDigestOf } from './consent.js'

/** A CRYPTOGRAPHIC content hash (SHA-256) — reproducible, collision-resistant. The
 *  receipt is a tamper-evident digest over exactly what changed; it also carries the
 *  action digest so a receipt can be tied back to the specific approved action. A
 *  full external signature (in-toto/SLSA, an injected signer) is the next step; the
 *  hash is no longer a 32-bit FNV that could be forged. */
export function attest(action: Action, status: ActionStatus, before: string | null, after: string | null, consentBy: string | null, now: number): Attestation {
  const actionDigest = actionDigestOf(action)
  const body = JSON.stringify({ kind: action.kind, target: action.target, params: action.params, actionDigest, status, before, after, consentBy, at: now })
  return {
    receipt: `att-sha256-${createHash('sha256').update(body).digest('hex').slice(0, 32)}`,
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
