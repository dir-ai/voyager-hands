# @dir-ai/voyager-hands

**Voyager's hands** — the *consent-gated remediation* organ. The senses observe
(read-only, autonomous). The hands **act** — but never freely.

An action here is:
- **Declarative**, drawn from a **known-safe catalog** — there is no free-form
  shell anywhere in the package by construction.
- Carrying its **exact inverse** — an action with no inverse **cannot auto-apply**.
- Classified by **blast radius** (B0…B3), which sets the **consent tier**.
- Applied **only through an injected provider**, behind a **hard consent gate**,
  after a dry-run preview — then **verified**, **auto-rolled-back** on regression,
  and **attested**.

> **The separation is the product.** Sensing is autonomous; acting is gated,
> reversible, and accountable. The hands never act on their own.

## Install

```bash
npm i -g @dir-ai/voyager-hands
```

## The pipeline

```
finding ─▶ plan ─▶ (declarative action + exact inverse, from the catalog)
                    │
                    ▼ preview  (dry-run: blast radius, consent tier, diff, blockers — touches nothing)
                    │
                    ▼ HARD CONSENT GATE  (B0 policy-auto · B1 policy+notify · B2 human · B3 two-person)
                    │
                    ▼ apply    (only with an injected provider + consent + execute:true)
                    │
                    ▼ verify   (re-sense; auto-rollback on regression)
                    │
                    ▼ attest   (a tamper-evident receipt of exactly what changed)
```

## Use (library)

```ts
import { plan, buildAction, apply, MemoryDnsProvider } from '@dir-ai/voyager-hands'

// 1. plan a reversible remediation for a finding (e.g. voyager-net's missing-dmarc)
const [proposal] = plan({ kind: 'missing-dmarc', target: 'example.com' })

// 2. build the concrete action (validated against the catalog; carries its inverse)
const action = buildAction(proposal.kind, proposal.target, proposal.params)

// 3. apply — DRY-RUN by default; a real change needs YOUR provider + explicit consent
const provider = new MyDnsProvider(/* least-privilege, scoped credential */)
const result = await apply(action, {
  provider,
  execute: true,
  consent: { approved: true, by: 'you@example.com' }, // an explicit decision, from a human/policy
})
// result.status ∈ 'previewed' | 'withheld' | 'applied' | 'rolled-back' | 'failed'
// result.attestation.receipt  ← the audit trail
```

The `Provider` is **injected** — the package holds no credentials and talks to no
real API by itself. Implement `read(target)` + `apply(action)` with a scoped,
least-privilege credential. A `MemoryDnsProvider` ships for tests and the demo.

## CLI

```bash
voyager-hands plan --kind missing-dmarc --target example.com    # propose
voyager-hands preview --kind dns.record.add --target example.com --type TXT --name _dmarc --value "v=DMARC1; p=none;"
voyager-hands demo                                              # full pipeline on an in-memory zone
```

Applying to a **real** system is intentionally *not* a one-command CLI action — it
needs the library with an injected provider + consent.

## MCP

```json
{ "command": "voyager-hands", "args": ["mcp"] }
```

Two tools, both **non-mutating**: `plan_remediation` and `preview_action`. There
is **no apply tool** — an agent can propose and preview, but can never mutate a
real system through MCP.

## Safety invariants

- **Never free-form.** Only catalog actions exist; no shell, ever.
- **Reversible or refused.** No inverse ⇒ blocked (needs a runbook / two-person path).
- **Dry-run by default.** Mutation requires `execute:true` **and** an injected provider **and** tier-appropriate consent.
- **Consent is explicit.** `approved:true` from a finding, a config, or the model is invalid — it must be a decision passed here. B3 requires two distinct approvers.
- **Auto-rollback.** A failing verification rolls back to the prior state.
- **Attested.** Every outcome carries a tamper-evident receipt.
- **Least privilege.** The package holds no credentials; the provider you inject does.

## First slice

DNS records (SPF / DMARC / CAA), the natural pair for
[`@dir-ai/voyager-net`](https://www.npmjs.com/package/@dir-ai/voyager-net)'s DNS
findings — reversible and low-blast. More catalogs (security headers via a config
provider, ACME cert renewal, firewall/SG rules at higher consent tiers) follow the
same pipeline. The line stays fixed: **anything that changes state is declarative,
reversible, gated, verified, and attested — or it is refused.**

## The Voyager family

The hands complete the organism: the senses ([`voyager`](https://www.npmjs.com/package/@dir-ai/voyager), [`voyager-browser`](https://www.npmjs.com/package/@dir-ai/voyager-browser), [`voyager-repo`](https://www.npmjs.com/package/@dir-ai/voyager-repo), [`voyager-net`](https://www.npmjs.com/package/@dir-ai/voyager-net)) observe, the [`voyager-contract`](https://www.npmjs.com/package/@dir-ai/voyager-contract) reasons, the [`voyager-agent`](https://www.npmjs.com/package/@dir-ai/voyager-agent) orchestrates — and **`voyager-hands` acts, through consent.**

## License

MIT © dir-ai
