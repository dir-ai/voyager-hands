#!/usr/bin/env node
/**
 * voyager-hands MCP server (stdio). It exposes only NON-MUTATING tools:
 * plan_remediation and preview_action. Actually APPLYING a change requires the
 * library with an injected provider + explicit consent — it is deliberately NOT
 * an MCP tool, so an agent can propose and preview but can never mutate a real
 * system through this server.
 */
import { Server } from '@modelcontextprotocol/sdk/server/index.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js'
import { plan } from './plan.js'
import { buildAction } from './catalog.js'
import { preview } from './apply.js'
import { VERSION } from './version.js'

const server = new Server({ name: 'voyager-hands', version: VERSION }, { capabilities: { tools: {} } })

const TOOLS = [
  {
    name: 'plan_remediation',
    description:
      "Propose REVERSIBLE remediations for a finding (e.g. missing-dmarc / missing-caa / missing-spf on a DNS zone). Returns declarative actions from a known-safe catalog, each with whether it is `ready` or needs operator input. The hands NEVER guess mail-affecting content (SPF senders) or a CA. This only PROPOSES — it does not preview against a real system or apply anything.",
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {
        kind: { type: 'string', minLength: 1, maxLength: 64, description: 'The finding kind to remediate.' },
        target: { type: 'string', minLength: 1, maxLength: 253, description: 'The resource (e.g. a DNS zone).' },
        rua: { type: 'string', maxLength: 253 },
        ca: { type: 'string', maxLength: 253 },
        spf: { type: 'string', maxLength: 512 },
      },
      required: ['kind', 'target'],
    },
  },
  {
    name: 'preview_action',
    description:
      "Dry-run a concrete declarative action (e.g. dns.record.add): compute its BLAST RADIUS, the CONSENT tier it demands, whether it is reversible, and any hard blockers. Touches nothing and applies nothing. Applying requires the library with an injected provider + explicit consent — never available through MCP.",
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {
        kind: { type: 'string', minLength: 1, maxLength: 64, description: 'Catalog action kind, e.g. dns.record.add.' },
        target: { type: 'string', minLength: 1, maxLength: 253 },
        type: { type: 'string', maxLength: 16 },
        name: { type: 'string', maxLength: 253 },
        value: { type: 'string', maxLength: 2048 },
      },
      required: ['kind', 'target'],
    },
  },
] as const

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }))

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { name, arguments: args = {} } = req.params
  const a = args as Record<string, unknown>
  const s = (k: string): string => (typeof a[k] === 'string' ? (a[k] as string) : '')
  const ok = (data: unknown, isError = false) => ({ content: [{ type: 'text' as const, text: JSON.stringify(data, null, 2) }], ...(isError ? { isError: true } : {}) })
  const err = (m: string) => ok({ error: m }, true)

  try {
    if (name === 'plan_remediation') {
      if (!s('kind') || !s('target')) return err('kind and target required')
      const params: Record<string, string> = {}
      for (const k of ['rua', 'ca', 'spf']) if (s(k)) params[k] = s(k)
      return ok({ proposals: plan({ kind: s('kind'), target: s('target'), params }) })
    }
    if (name === 'preview_action') {
      const action = buildAction(s('kind'), s('target'), { type: s('type'), name: s('name'), value: s('value') })
      return ok({ preview: await preview(action) })
    }
    return err(`Unknown tool: ${name}`)
  } catch (e) {
    return err(e instanceof Error ? e.message : String(e))
  }
})

export async function startMcpServer(): Promise<void> {
  const transport = new StdioServerTransport()
  await server.connect(transport)
  console.error(`voyager-hands MCP server v${VERSION} ready (stdio) — propose + preview only, never mutates`)
}

import { fileURLToPath } from 'node:url'
import { realpathSync } from 'node:fs'
function isDirectEntry(): boolean {
  const argv1 = process.argv[1]
  if (!argv1) return false
  const self = fileURLToPath(import.meta.url)
  try {
    return realpathSync(self) === realpathSync(argv1)
  } catch {
    return self === argv1
  }
}
if (isDirectEntry()) {
  startMcpServer().catch((e) => {
    console.error(e instanceof Error ? e.stack : String(e))
    process.exit(1)
  })
}
