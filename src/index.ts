// @dir-ai/voyager-hands — Voyager's HANDS: the consent-gated remediation organ.
//
// The senses observe (read-only, autonomous). The hands ACT — but never freely:
// an action is DECLARATIVE (drawn from a known-safe catalog, never free-form
// shell), carries its exact INVERSE (or it cannot auto-apply), is classified by
// BLAST RADIUS, previews as a dry-run, and can only mutate through an INJECTED
// provider behind a HARD CONSENT GATE, after which it verifies and auto-rolls-back
// on regression and attests. The separation — sensing vs acting — is the product.
export { plan, type Finding, type Proposal } from './plan.js'
export { buildAction, CATALOG, entryFor } from './catalog.js'
export { preview, apply, type ApplyOptions } from './apply.js'
export { blastToTier, consentGate, requiresHuman } from './consent.js'
export { attest } from './attest.js'
export { MemoryDnsProvider } from './providers.js'
export type {
  Action, CatalogEntry, BlastClass, ConsentTier, ActionStatus,
  Preview, Consent, Attestation, ApplyResult, Provider,
} from './types.js'
export { VERSION } from './version.js'
