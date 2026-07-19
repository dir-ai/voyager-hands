import type { Action, Provider } from './types.js'

/** An in-memory DNS provider — for tests, demos, and dry-runs. REAL providers
 *  (Cloudflare, Route 53, …) are the CALLER's job: implement `Provider` with a
 *  least-privilege, scoped credential. The package ships only the interface + this
 *  memory one, so it can never hold a real credential or touch a real zone itself. */
export class MemoryDnsProvider implements Provider {
  readonly name = 'memory-dns'
  private records = new Map<string, string>()

  constructor(seed: Record<string, string> = {}) {
    for (const [k, v] of Object.entries(seed)) this.records.set(k, v)
  }

  private key(target: string, type?: string, name?: string): string {
    return `${target}|${(type ?? '').toUpperCase()}|${name ?? ''}`
  }

  async read(target: string): Promise<string | null> {
    const here = [...this.records.entries()].filter(([k]) => k.startsWith(`${target}|`)).map(([k, v]) => `${k.split('|').slice(1).join(' ')}=${v}`)
    return here.length ? here.sort().join('\n') : null
  }

  async apply(action: Action): Promise<void> {
    const { type, name, value } = action.params
    const k = this.key(action.target, type, name)
    if (action.kind === 'dns.record.add') this.records.set(k, value)
    else if (action.kind === 'dns.record.delete') this.records.delete(k)
    else throw new Error(`memory provider does not implement ${action.kind}`)
  }
}
