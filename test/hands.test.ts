import { test } from 'node:test'
import assert from 'node:assert/strict'
import { plan, buildAction, preview, apply, consentGate, blastToTier, actionDigestOf, MemoryDnsProvider } from '../dist/index.js'
import type { Action, Provider } from '../dist/index.js'

const NOW = 1_700_000_000_000
const dmarc = () => buildAction('dns.record.add', 'example.com', { type: 'TXT', name: '_dmarc', value: 'v=DMARC1; p=none;' })

test('plan: safe DMARC is ready; SPF/CAA that could break things are NOT auto-filled', () => {
  assert.equal(plan({ kind: 'missing-dmarc', target: 'x.com' })[0].ready, true)
  assert.equal(plan({ kind: 'missing-spf', target: 'x.com' })[0].ready, false) // never guesses senders
  assert.equal(plan({ kind: 'missing-caa', target: 'x.com' })[0].ready, false) // needs the CA
  assert.equal(plan({ kind: 'missing-caa', target: 'x.com', params: { ca: 'letsencrypt.org' } })[0].ready, true)
  assert.equal(plan({ kind: 'not-a-thing', target: 'x.com' }).length, 0)
})

test('buildAction: refuses anything not in the catalog and invalid params', () => {
  assert.throws(() => buildAction('shell.exec', 'x', { cmd: 'rm -rf /' }), /known-safe catalog/)
  assert.throws(() => buildAction('dns.record.add', 'x', { type: 'TXT', name: '@' }), /value is required/)
  const a = dmarc()
  assert.equal(a.reversible, true)
  assert.equal(a.inverse?.kind, 'dns.record.delete') // carries its exact inverse
})

test('blast → consent tier matrix', () => {
  assert.equal(blastToTier('B0'), 'policy-auto')
  assert.equal(blastToTier('B2'), 'human-required')
  assert.equal(blastToTier('B3'), 'two-person')
})

test('consent gate: policy tiers accept unbound; human/two-person REQUIRE an action-bound approval', () => {
  assert.ok(consentGate('policy-auto', undefined)) // no consent → refused
  assert.equal(consentGate('policy-auto', { approved: true, by: 'policy:x' }), null) // B0/B1 unbound ok
  assert.ok(consentGate('human-required', { approved: true, by: '' })) // needs an identity
  // human-required now needs the approval bound to THIS action (anti-replay)
  const a = dmarc()
  const digest = actionDigestOf(a)
  assert.ok(consentGate('human-required', { approved: true, by: 'alice' }, a)) // unbound → refused
  assert.equal(consentGate('human-required', { approved: true, by: 'alice', actionDigest: digest }, a), null)
  // a bound approval for a DIFFERENT action is refused
  assert.ok(consentGate('human-required', { approved: true, by: 'alice', actionDigest: 'deadbeef' }, a))
  // two-person: bound + two distinct approvers
  assert.ok(consentGate('two-person', { approved: true, by: 'a', actionDigest: digest }, a)) // second missing
  assert.ok(consentGate('two-person', { approved: true, by: 'a', secondBy: 'a', actionDigest: digest }, a)) // must differ
  assert.equal(consentGate('two-person', { approved: true, by: 'a', secondBy: 'b', actionDigest: digest }, a), null)
  // an EXPIRED approval is refused
  assert.ok(consentGate('policy-auto', { approved: true, by: 'p', expiresAt: NOW - 1 }, a, NOW))
})

test('apply: default is DRY-RUN — nothing mutates without execute', async () => {
  const provider = new MemoryDnsProvider()
  const r = await apply(dmarc(), { provider, now: NOW })
  assert.equal(r.status, 'previewed')
  assert.equal(await provider.read('example.com'), null) // zone untouched
})

test('apply: execute without a provider or without consent is WITHHELD (fail-closed)', async () => {
  const noProv = await apply(dmarc(), { execute: true, consent: { approved: true, by: 'p' }, now: NOW })
  assert.equal(noProv.status, 'withheld')
  const noConsent = await apply(dmarc(), { provider: new MemoryDnsProvider(), execute: true, now: NOW })
  assert.equal(noConsent.status, 'withheld')
})

test('apply: with provider + consent + verify → applied, verified, attested (mutated)', async () => {
  const provider = new MemoryDnsProvider()
  // _dmarc TXT is now B1 (policy-notify) — a policy approval suffices; verify confirms.
  const r = await apply(dmarc(), { provider, execute: true, consent: { approved: true, by: 'policy:dns' }, verify: async () => true, now: NOW })
  assert.equal(r.status, 'applied')
  assert.equal(r.verification?.passed, true)
  assert.equal(r.mutated, true)
  assert.match(r.attestation.receipt, /^att-sha256-/)
  assert.match((await provider.read('example.com')) ?? '', /DMARC1/)
})

test('apply: WITHOUT a verify fn → applied but reported NOT verified (a state change is not proof)', async () => {
  const provider = new MemoryDnsProvider()
  const r = await apply(dmarc(), { provider, execute: true, consent: { approved: true, by: 'policy:dns' }, now: NOW })
  assert.equal(r.status, 'applied')
  assert.equal(r.verification?.passed, null) // honest: unverified, not a false "true"
  assert.ok(r.notes.some((n) => /NOT verified/i.test(n)))
})

// ── P0-C: transactional apply — a throw AFTER a mutation is never "no change" ──
test('apply: provider mutates THEN throws → detected via read-back, rolled back, mutated flagged', async () => {
  const store = new Map<string, string>()
  const provider: Provider = {
    async read(t) { return store.get(t) ?? null },
    async apply(a) {
      if (a.kind === 'dns.record.add') { store.set(a.target, a.params.value); throw new Error('network dropped after write') }
      store.delete(a.target) // the inverse (delete) succeeds
    },
  }
  const r = await apply(dmarc(), { provider, execute: true, consent: { approved: true, by: 'policy:dns' }, now: NOW })
  assert.notEqual(r.status, 'applied')
  assert.equal(r.mutated, true, 'the partial mutation is detected, not reported as no-change')
  assert.equal(r.status, 'rolled-back') // inverse restored the prior (empty) state
  assert.equal(store.get('example.com'), undefined) // confirmed restored
})

test('buildAction: DNS blast depends on record TYPE — MX is B2, plain TXT is B0, _dmarc is B1', () => {
  assert.equal(buildAction('dns.record.add', 'x.com', { type: 'MX', name: '@', value: '10 mail.x.com' }).blastClass, 'B2')
  assert.equal(buildAction('dns.record.add', 'x.com', { type: 'TXT', name: 'random', value: 'hello' }).blastClass, 'B0')
  assert.equal(dmarc().blastClass, 'B1') // _dmarc TXT affects mail
})

test('apply: a failing verify triggers AUTO-ROLLBACK to the prior state', async () => {
  const provider = new MemoryDnsProvider()
  const r = await apply(dmarc(), {
    provider, execute: true, consent: { approved: true, by: 'policy:dns-b0' }, now: NOW,
    verify: async () => false, // simulate the fix not holding
  })
  assert.equal(r.status, 'rolled-back')
  assert.equal(r.rolledBack, true)
  assert.equal(await provider.read('example.com'), null) // rolled back to empty
})

test('preview: an irreversible action (delete with no captured value) is BLOCKED', async () => {
  const del: Action = buildAction('dns.record.delete', 'example.com', { type: 'TXT', name: '_dmarc' })
  assert.equal(del.reversible, false) // no value captured → no inverse
  const p = await preview(del)
  assert.ok(p.blockers.length >= 1)
  const r = await apply(del, { provider: new MemoryDnsProvider(), execute: true, consent: { approved: true, by: 'p' }, now: NOW })
  assert.equal(r.status, 'withheld') // refused outright, never applied
})
