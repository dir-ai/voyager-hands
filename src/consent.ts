import type { BlastClass, Consent, ConsentTier } from './types.js'

/** The blast-radius → consent-tier matrix. The whole safety model in one table:
 *  the bigger the blast, the more approval required, and B3 is never auto. */
export function blastToTier(blast: BlastClass): ConsentTier {
  switch (blast) {
    case 'B0':
      return 'policy-auto'
    case 'B1':
      return 'policy-notify'
    case 'B2':
      return 'human-required'
    case 'B3':
      return 'two-person'
  }
}

export function requiresHuman(tier: ConsentTier): boolean {
  return tier === 'human-required' || tier === 'two-person'
}

/** The HARD, non-bypassable consent gate. Returns a reason string if consent is
 *  NOT sufficient for the tier (mutation must be refused), or null if it passes.
 *  Consent must be an explicit decision — `approved:true` alone is not enough for
 *  the human/two-person tiers. */
export function consentGate(tier: ConsentTier, consent: Consent | undefined): string | null {
  if (!consent || consent.approved !== true) return 'no explicit approval — action withheld'
  if (!consent.by || !consent.by.trim()) return 'approval is missing an approver identity'
  if (tier === 'two-person') {
    if (!consent.secondBy || !consent.secondBy.trim()) return 'this blast class (B3) requires TWO-PERSON approval — a second approver is missing'
    if (consent.secondBy.trim() === consent.by.trim()) return 'the two approvers must be different people'
  }
  // human-required: `by` present is sufficient (the caller asserts it's a human).
  return null
}
