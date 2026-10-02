import { readFile } from 'node:fs/promises'
import {
  acquireReconnectLock,
  loadCredentialsWithLockHeld,
  refreshCredentials,
  type StoredCredentials,
  type TokenDependencies,
} from './auth.js'
import { CliError, objectValue, postWithoutRedirect, readJsonResponse } from './http.js'
import operationManifest from './generated/operations.json' with { type: 'json' }

export interface CliOperation {
  name: string
  description: string
  scopes: string[]
  conditionalScopes: Array<{ when: string; scopes: string[] }>
  example: unknown
  path: string
  requiresIdempotency: boolean
  risk: 'read' | 'low_write' | 'high_write'
}

interface Manifest {
  contractVersion: 'v1'
  operations: CliOperation[]
}

const manifest = operationManifest as Manifest
const operationsByName = new Map(manifest.operations.map((operation) => [operation.name, operation]))

export function listOperations(): CliOperation[] {
  return structuredClone(manifest.operations)
}

export async function readOperationInput(
  options: { input?: string; inputFile?: string },
  fileReader: (path: string, encoding: BufferEncoding) => Promise<string> = readFile,
): Promise<Record<string, unknown>> {
  if (options.input !== undefined && options.inputFile !== undefined) {
    throw new CliError('Use either --input or --input-file, not both.')
  }
  let source = '{}'
  if (options.input !== undefined) source = options.input
  if (options.inputFile !== undefined) source = await fileReader(options.inputFile, 'utf8')
  try {
    return objectValue(JSON.parse(source), 'Operation input')
  } catch (caught) {
    if (caught instanceof CliError) throw caught
    throw new CliError('Operation input must be valid JSON object data.')
  }
}

export interface OperationDependencies extends TokenDependencies {
  origin: string
  randomBytes(size: number): Uint8Array
}

function idempotentInput(
  operation: CliOperation,
  input: Record<string, unknown>,
  randomBytes: (size: number) => Uint8Array,
): Record<string, unknown> {
  if (!operation.requiresIdempotency || typeof input.idempotencyKey === 'string') return input
  return { ...input, idempotencyKey: Buffer.from(randomBytes(24)).toString('base64url') }
}

async function requestWithTransportRetry(
  operation: CliOperation,
  input: Record<string, unknown>,
  credentials: StoredCredentials,
  dependencies: OperationDependencies,
): Promise<Response> {
  let firstError: unknown
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      return await postWithoutRedirect(dependencies.fetch, `${dependencies.origin}${operation.path}`, {
        headers: {
          authorization: `Bearer ${credentials.accessToken}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify(input),
      }, 'Operation request')
    } catch (caught) {
      if (caught instanceof CliError) throw caught
      firstError = caught
    }
  }
  throw new CliError(`Operation transport failed: ${firstError instanceof Error ? firstError.message : 'request failed'}`)
}

export interface AgentErrorEnvelope {
  error: {
    code: string
    message: string
    retryable: boolean
    retryAfterSeconds?: number
    details?: Record<string, unknown>
  }
}

export class OperationError extends CliError {
  constructor(
    readonly envelope: AgentErrorEnvelope,
    readonly origin: string,
    readonly idempotencyKey?: string,
  ) {
    super(`${envelope.error.code}: ${envelope.error.message}`)
    this.name = 'OperationError'
  }
}

function agentErrorEnvelope(value: unknown): value is AgentErrorEnvelope {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  const error = (value as Record<string, unknown>).error
  if (!error || typeof error !== 'object' || Array.isArray(error)) return false
  const candidate = error as Record<string, unknown>
  return typeof candidate.code === 'string'
    && typeof candidate.message === 'string'
    && typeof candidate.retryable === 'boolean'
}

async function operationError(
  response: Response,
  origin: string,
  idempotencyKey: string | undefined,
): Promise<CliError> {
  let value: unknown
  try {
    value = await response.json()
  } catch {
    return new CliError(`Operation failed with HTTP ${response.status}.`)
  }
  if (agentErrorEnvelope(value)) {
    return new OperationError(structuredClone(value), origin, idempotencyKey)
  }
  if (value && typeof value === 'object') {
    const outer = value as Record<string, unknown>
    if (outer.error && typeof outer.error === 'object') {
      const error = outer.error as Record<string, unknown>
      if (typeof error.code === 'string' && typeof error.message === 'string') {
        return new CliError(`${error.code}: ${error.message}`)
      }
    }
    if (typeof outer.error === 'string') return new CliError(`${outer.error}: authentication failed.`)
  }
  return new CliError(`Operation failed with HTTP ${response.status}.`)
}

async function callOperationWithLockHeld(
  name: string,
  rawInput: Record<string, unknown>,
  dependencies: OperationDependencies,
): Promise<unknown> {
  const operation = operationsByName.get(name)
  if (!operation) throw new CliError(`Unknown operation: ${name}`)
  let loaded = await loadCredentialsWithLockHeld(dependencies.origin, dependencies)
  if (!loaded) throw new CliError('Not connected. Run athlendra connect first.')
  if (loaded.credentials.expiresAt <= dependencies.now() + 60_000) {
    loaded = await refreshCredentials(loaded, dependencies)
  }
  const input = idempotentInput(operation, rawInput, dependencies.randomBytes)
  const effectiveIdempotencyKey = typeof input.idempotencyKey === 'string'
    ? input.idempotencyKey
    : undefined
  let response = await requestWithTransportRetry(operation, input, loaded.credentials, dependencies)
  if (response.status === 401) {
    loaded = await refreshCredentials(loaded, dependencies)
    response = await requestWithTransportRetry(operation, input, loaded.credentials, dependencies)
  }
  if (!response.ok) throw await operationError(response, dependencies.origin, effectiveIdempotencyKey)
  return readJsonResponse(response, 'Operation')
}

export async function callOperation(
  name: string,
  rawInput: Record<string, unknown>,
  dependencies: OperationDependencies,
): Promise<unknown> {
  const release = await acquireReconnectLock(dependencies.origin, dependencies)
  try {
    return await callOperationWithLockHeld(name, rawInput, dependencies)
  } finally {
    await release()
  }
}
