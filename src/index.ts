#!/usr/bin/env node
import { realpathSync } from 'node:fs'
import { readFile } from 'node:fs/promises'
import { pathToFileURL } from 'node:url'
import { Command, CommanderError, Option } from 'commander'
import open from 'open'
import {
  connect,
  logout,
  resolveOrigin,
  systemRandomBytes,
  type AuthDependencies,
} from './auth.js'
import { loopbackCallbackServer } from './callback-server.js'
import { callOperation, listOperations, OperationError, readOperationInput } from './commands.js'
import { nativeCredentialStore } from './credentials.js'
import { CliError } from './http.js'
import {
  formatConnected,
  formatOperationError,
  formatOperationResult,
  printableIdempotencyKey,
  stableJson,
} from './output.js'

export interface CliDependencies extends AuthDependencies {
  originEnvironment: string | undefined
  readFile(path: string, encoding: BufferEncoding): Promise<string>
  stdout(text: string): void
  stderr(text: string): void
}

const defaults: CliDependencies = {
  originEnvironment: process.env.ATHLENDRA_ORIGIN,
  fetch: globalThis.fetch,
  browserOpen: (url) => open(url),
  callbackServer: loopbackCallbackServer,
  credentials: nativeCredentialStore,
  now: Date.now,
  randomBytes: systemRandomBytes,
  readFile,
  stdout: (text) => process.stdout.write(text),
  stderr: (text) => process.stderr.write(text),
}

function collect(value: string, previous: string[]): string[] {
  return [...previous, value]
}

function commandOrigin(program: Command, dependencies: CliDependencies): string {
  return resolveOrigin(program.opts<{ origin?: string }>().origin, dependencies.originEnvironment)
}

function operationListing(): string {
  return listOperations().map((operation) => {
    const conditional = operation.conditionalScopes.length > 0
      ? [
          `  Conditional scopes: ${operation.conditionalScopes
            .map(({ when, scopes }) => `${scopes.join(', ')} when ${when}`)
            .join('; ')}`,
          '  Least privilege: request conditional scopes only when their condition applies.',
        ]
      : []
    return [
      operation.name,
      `  ${operation.description}`,
      `  Scopes: ${operation.scopes.join(', ')}`,
      ...conditional,
      `  Example: ${stableJson(operation.example)}`,
    ].join('\n')
  }).join('\n') + '\n'
}

function buildProgram(dependencies: CliDependencies): Command {
  const program = new Command()
    .name('athlendra')
    .description('Call a configured Athlendra agent API')
    .version('0.1.0')
    .option('--origin <url>', 'Athlendra origin; or set ATHLENDRA_ORIGIN')
    .exitOverride()
    .configureOutput({
      writeOut: dependencies.stdout,
      writeErr: dependencies.stderr,
    })

  program.command('connect')
    .description('Connect through browser OAuth and the OS keyring')
    .addOption(new Option('--profile <profile>', 'scope profile').choices(['read', 'full']).default('read'))
    .option('--scope <scope>', 'request one released scope; repeat for more', collect, [])
    .action(async (options: { profile: 'read' | 'full'; scope: string[] }) => {
      const origin = commandOrigin(program, dependencies)
      const result = await connect({
        origin,
        profile: options.profile,
        scopes: options.scope.length > 0 ? options.scope : undefined,
      }, dependencies)
      dependencies.stdout(formatConnected(result.origin, result.scopes))
    })

  program.command('operations')
    .description('List released operations')
    .action(() => dependencies.stdout(operationListing()))

  program.command('call')
    .description('Call one released operation')
    .argument('<operation>', 'operation name')
    .option('--input <json>', 'inline JSON object input')
    .option('--input-file <path>', 'path to a JSON object input')
    .option('--json', 'print the full stable response envelope')
    .action(async (name: string, options: { input?: string; inputFile?: string; json?: boolean }) => {
      const origin = commandOrigin(program, dependencies)
      const input = await readOperationInput(options, dependencies.readFile)
      try {
        const result = await callOperation(name, input, { ...dependencies, origin })
        dependencies.stdout(formatOperationResult(result, Boolean(options.json)))
      } catch (caught) {
        if (!(caught instanceof OperationError)) throw caught
        if (options.json) {
          dependencies.stdout(`${stableJson(caught.envelope)}\n`)
          const retryKey = printableIdempotencyKey(caught.idempotencyKey)
          if (retryKey) {
            dependencies.stderr(`Retry idempotency key: ${retryKey}\n`)
          }
        } else {
          dependencies.stderr(formatOperationError(caught))
        }
        caught.reported = true
        throw caught
      }
    })

  program.command('logout')
    .description('Delete credentials for the configured origin')
    .action(async () => {
      await logout(commandOrigin(program, dependencies), dependencies)
      dependencies.stdout('Logged out.\n')
    })

  return program
}

export async function runCli(argv: string[], dependencies: CliDependencies = defaults): Promise<number> {
  try {
    await buildProgram(dependencies).parseAsync(argv)
    return 0
  } catch (caught) {
    if (caught instanceof CommanderError && caught.code === 'commander.helpDisplayed') return 0
    const exitCode = caught instanceof CliError
      ? caught.exitCode
      : caught instanceof CommanderError ? caught.exitCode : 1
    if (!(caught instanceof CommanderError) && !(caught instanceof CliError && caught.reported)) {
      const message = caught instanceof Error ? caught.message : 'Command failed.'
      dependencies.stderr(`Error: ${message}\n`)
    }
    return exitCode
  }
}

function isMainModule(): boolean {
  const entry = process.argv[1]
  if (!entry) return false
  try {
    return pathToFileURL(realpathSync(entry)).href === import.meta.url
  } catch {
    return false
  }
}

if (isMainModule()) {
  void runCli(process.argv).then((exitCode) => {
    process.exitCode = exitCode
  })
}
