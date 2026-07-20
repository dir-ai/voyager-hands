import { promises as fs } from 'node:fs'
import { resolve, relative, isAbsolute } from 'node:path'
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

/**
 * A file-edit provider — the EDIT-ON-THE-FLY organ. Scoped to a single root
 * directory: every target path is realpath-contained under `root`, so a `file`
 * param can never escape it (no editing ~/.ssh via ../../). It implements only
 * `file.replace` (exact string → exact string), and — like the DNS provider — the
 * hands pipeline still gates it: dry-run by default, consent required, read-back +
 * verify + auto-rollback on regression. The caller injects it with the scope it
 * trusts; the package holds no path of its own.
 */
export class FileProvider implements Provider {
  readonly name = 'file'
  constructor(private readonly root: string) {}

  private async contained(target: string): Promise<string | null> {
    const abs = isAbsolute(target) ? target : resolve(this.root, target)
    try {
      const realRoot = await fs.realpath(this.root)
      const realTarget = await fs.realpath(abs).catch(() => abs) // may not exist yet
      const rel = relative(realRoot, realTarget)
      return rel.startsWith('..') || isAbsolute(rel) ? null : realTarget
    } catch {
      return null
    }
  }

  async read(target: string): Promise<string | null> {
    const p = await this.contained(target)
    if (!p) return null
    try {
      return await fs.readFile(p, 'utf8')
    } catch {
      return null
    }
  }

  async apply(action: Action): Promise<void> {
    if (action.kind !== 'file.replace') throw new Error(`file provider does not implement ${action.kind}`)
    const p = await this.contained(action.target)
    if (!p) throw new Error(`refused: ${action.target} is outside the provider root (containment)`)
    const before = await fs.readFile(p, 'utf8')
    const { find, to } = action.params
    if (!before.includes(find)) throw new Error('the exact `find` text is not present in the file — refusing to edit blindly')
    // Replace the FIRST occurrence only (a precise, predictable edit).
    await fs.writeFile(p, before.replace(find, to), 'utf8')
  }
}
