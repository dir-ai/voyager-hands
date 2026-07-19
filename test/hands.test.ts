import { test } from 'node:test'
import assert from 'node:assert/strict'
import { plan, buildAction, preview, apply, consentGate, blastToTier, MemoryDnsProvider } from '../dist/index.js'
import type { Action } from '../dist/index.js'

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

test('consent gate: B0 still needs explicit approval; B3 needs two DISTINCT approvers', () => {
  assert.ok(consentGate('policy-auto', undefined)) // no consent → refused
  assert.equal(consentGate('policy-auto', { approved: true, by: 'policy:x' }), null)
  assert.ok(consentGate('human-required', { approved: true, by: '' })) // needs an identity
  assert.ok(consentGate('two-person', { approved: true, by: 'a' })) // second approver missing
  assert.ok(consentGate('two-person', { approved: true, by: 'a', secondBy: 'a' })) // must be different
  assert.equal(consentGate('two-person', { approved: true, by: 'a', secondBy: 'b' }), null)
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

test('apply: with provider + consent → applied, verified, attested', async () => {
  const provider = new MemoryDnsProvider()
  const r = await apply(dmarc(), { provider, execute: true, consent: { approved: true, by: 'policy:dns-b0' }, now: NOW })
  assert.equal(r.status, 'applied')
  assert.equal(r.verification?.passed, true)
  assert.match(r.attestation.receipt, /^att-/)
  assert.match((await provider.read('example.com')) ?? '', /DMARC1/)
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
