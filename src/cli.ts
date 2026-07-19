#!/usr/bin/env node
/**
 * voyager-hands CLI. PROPOSE and PREVIEW remediations safely. Actually APPLYING
 * requires the library with an INJECTED provider + explicit consent — it is not a
 * one-command mutation, by design.
 */
import { plan, type Finding } from './plan.js'
import { buildAction } from './catalog.js'
import { preview, apply } from './apply.js'
import { MemoryDnsProvider } from './providers.js'
import { VERSION } from './version.js'

function parseArgs(argv: string[]): { flags: Record<string, string>; positionals: string[] } {
  const flags: Record<string, string> = {}
  const positionals: string[] = []
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a.startsWith('--')) { flags[a.slice(2)] = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : 'true' } else positionals.push(a)
  }
  return { flags, positionals }
}

const HELP = `voyager-hands v${VERSION} — the consent-gated remediation organ

USAGE
  voyager-hands plan --kind <finding-kind> --target <zone> [--rua m@x] [--ca letsencrypt.org] [--spf "v=spf1 …"]
        Propose reversible remediations for a finding (e.g. missing-dmarc /
        missing-caa / missing-spf). The hands NEVER guess mail-affecting content.

  voyager-hands preview --kind <action-kind> --target <zone> --type TXT --name _dmarc --value "v=DMARC1; p=none;"
        Dry-run a concrete action: blast radius, the consent it demands, the
        before→after diff, and any hard blockers. Touches nothing.

  voyager-hands demo
        Run the full pipeline against an in-memory zone: dry-run → consent gate →
        apply → verify → attest → auto-rollback. No real DNS involved.

  voyager-hands help | --version

Applying to a REAL zone needs the library with an injected Provider + Consent —
never a single CLI command. The senses observe; the hands act only through consent.`

async function main(): Promise<number> {
  const [cmd, ...rest] = process.argv.slice(2)
  const { flags } = parseArgs(rest)
  if (cmd === '--version' || cmd === 'version') { console.log(VERSION); return 0 }

  if (cmd === 'mcp') {
    const { startMcpServer } = await import('./mcp.js')
    await startMcpServer()
    return new Promise<number>(() => {})
  }

  if (cmd === 'plan') {
    const finding: Finding = { kind: flags.kind, target: flags.target, params: { ...(flags.rua ? { rua: flags.rua } : {}), ...(flags.ca ? { ca: flags.ca } : {}), ...(flags.spf ? { spf: flags.spf } : {}) } }
    if (!finding.kind || !finding.target) { console.error('plan needs --kind and --target'); return 2 }
    const proposals = plan(finding)
    if (!proposals.length) { console.log(`no catalog remediation for "${finding.kind}"`); return 0 }
    for (const p of proposals) {
      console.log(`\n  ${p.ready ? '\x1b[32m✓ ready\x1b[0m' : '\x1b[33m needs input\x1b[0m'}  ${p.kind}  →  ${p.target}`)
      console.log(`    ${p.params.type} ${p.params.name} = ${p.params.value || '(supply a value)'}`)
      console.log(`    \x1b[2m${p.note}\x1b[0m`)
    }
    console.log('')
    return 0
  }

  if (cmd === 'preview') {
    try {
      const action = buildAction(flags.kind, flags.target, { type: flags.type, name: flags.name, value: flags.value })
      const p = await preview(action)
      console.log(`\n  action: ${action.summary}`)
      console.log(`  blast:  ${p.blastClass}  →  consent: ${p.consentTier}${p.requiresHuman ? ' (human required)' : ''}`)
      console.log(`  reversible: ${p.reversible}${p.blockers.length ? `\n  \x1b[31mBLOCKED: ${p.blockers.join('; ')}\x1b[0m` : ''}`)
      console.log(`  ${p.diff.replace(/\n/g, '\n  ')}\n`)
      return p.blockers.length ? 1 : 0
    } catch (e) {
      console.error(`\x1b[31m✗\x1b[0m ${e instanceof Error ? e.message : String(e)}`)
      return 2
    }
  }

  if (cmd === 'demo') {
    console.log('\n\x1b[1mvoyager-hands demo\x1b[0m — full pipeline on an in-memory zone (no real DNS)\n')
    const provider = new MemoryDnsProvider()
    const action = buildAction('dns.record.add', 'example.com', { type: 'TXT', name: '_dmarc', value: 'v=DMARC1; p=none;' })
    console.log('1) DRY-RUN (execute omitted):')
    const dry = await apply(action, { provider })
    console.log(`   status=${dry.status}  ${dry.notes[0]}`)
    console.log('2) EXECUTE without consent → withheld:')
    const noConsent = await apply(action, { provider, execute: true })
    console.log(`   status=${noConsent.status}  ${noConsent.notes.join(' | ')}`)
    console.log('3) EXECUTE with consent → applied + attested:')
    const done = await apply(action, { provider, execute: true, consent: { approved: true, by: 'policy:dns-b0' } })
    console.log(`   status=${done.status}  receipt=${done.attestation.receipt}  verified=${done.verification?.passed}`)
    console.log(`   zone now:\n     ${(await provider.read('example.com'))?.replace(/\n/g, '\n     ')}\n`)
    return 0
  }

  console.log(HELP)
  return 0
}

main().then((c) => process.exit(c)).catch((e) => { console.error(e instanceof Error ? (e.stack ?? e.message) : String(e)); process.exit(2) })
