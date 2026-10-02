import { describe, expect, it, vi } from 'vitest'
import {
  callOperation,
  listOperations,
  OperationError,
  readOperationInput,
} from '../src/commands'
import type { StoredCredentials } from '../src/auth'
import { runCli, type CliDependencies } from '../src/index'
import { nativeReconnectLock } from '../src/reconnect-lock'

const origin = 'https://commands.athlendra.example.test'
const issuer = 'https://app.athlendra.example.test'
const stagingAccount = `reconnect:v1:${origin}`
const credentials: StoredCredentials = {
  accessToken: 'ACCESS-SECRET',
  clientId: 'client',
  expiresAt: 1_900_000_000_000,
  origin,
  issuer,
  redirectUri: 'http://127.0.0.1:45678/oauth/callback',
  refreshToken: 'REFRESH-SECRET',
  scopes: ['clients:read', 'programs:write'],
  tokenEndpoint: `${issuer}/oauth/token`,
}

describe('operation commands', () => {
  it('runs operations and returns nonzero for operation errors', async () => {
    let output = ''
    let error = ''
    const dependencies: CliDependencies = {
      originEnvironment: undefined,
      fetch: vi.fn(async (input) => {
        expect(String(input)).toBe(`${origin}/api/agent/v1/operations/find_clients`)
        return Response.json({
          error: { code: 'validation_failed', message: 'Bad input.', retryable: false },
        }, { status: 422 })
      }),
      browserOpen: vi.fn(),
      callbackServer: { start: vi.fn() },
      credentials: {
        assertAvailable: async () => undefined,
        get: async () => credentials,
        set: async () => undefined,
        delete: async () => true,
      },
      now: () => 1_800_000_000_000,
      randomBytes: (size) => new Uint8Array(size).fill(9),
      readFile: vi.fn(),
      stdout: (text) => { output += text },
      stderr: (text) => { error += text },
    }

    expect(await runCli(['node', 'athlendra', '--origin', origin, 'operations'], dependencies)).toBe(0)
    expect(output).toContain('find_clients')
    expect(output).toContain('Conditional scopes: notes:read when includePrivateNotes is true')
    expect(output).toContain('request conditional scopes only when their condition applies')
    expect(await runCli([
      'node', 'athlendra', '--origin', origin, 'call', 'find_clients', '--input', '{"query":""}',
    ], dependencies)).toBe(1)
    expect(error).toContain('validation_failed: Bad input.')
    expect(error).not.toContain('ACCESS-SECRET')
  })

  it('lists generated operation names, descriptions, scopes, and examples', () => {
    const operations = listOperations()
    expect(operations).toContainEqual(expect.objectContaining({
      name: 'find_clients',
      description: 'Find clients by partial name or external reference.',
      scopes: ['clients:read'],
      example: { query: 'Alex' },
    }))
    expect(operations).toContainEqual(expect.objectContaining({ name: 'delete_planned_session' }))
    expect(operations).toContainEqual(expect.objectContaining({ name: 'create_exercise', example: expect.any(Object) }))
    expect(operations).toContainEqual(expect.objectContaining({ name: 'create_client', example: expect.any(Object) }))
    expect(operations).toContainEqual(expect.objectContaining({
      name: 'get_client', example: { clientId: expect.any(String) },
    }))
    expect(operations).toContainEqual(expect.objectContaining({
      name: 'update_exercise', example: expect.objectContaining({
        idempotencyKey: expect.any(String), exerciseId: expect.any(String), expectedVersion: '1',
      }),
    }))
    expect(operations).toContainEqual(expect.objectContaining({
      name: 'update_client', example: expect.objectContaining({
        idempotencyKey: expect.any(String), clientId: expect.any(String), expectedVersion: '1',
        name: expect.any(String), email: expect.any(String),
      }),
    }))
    expect(operations).toHaveLength(19)
    expect(operations.find(({ name }) => name === 'get_session')?.conditionalScopes).toEqual([
      { when: 'includePrivateNotes is true', scopes: ['notes:read'] },
    ])
    for (const name of ['validate_program', 'save_program_draft']) {
      expect(operations.find((operation) => operation.name === name)?.description)
        .toContain('https://github.com/jdelaire/open-workout-format/')
    }
  })

  it('reads inline JSON or a file, rejects ambiguous and malformed input', async () => {
    const readFile = vi.fn(async () => '{"clientId":"client-1"}')
    await expect(readOperationInput({ input: '{"query":"Alex"}' }, readFile))
      .resolves.toEqual({ query: 'Alex' })
    await expect(readOperationInput({ inputFile: 'request.json' }, readFile))
      .resolves.toEqual({ clientId: 'client-1' })
    expect(readFile).toHaveBeenCalledWith('request.json', 'utf8')
    await expect(readOperationInput({}, readFile)).resolves.toEqual({})
    await expect(readOperationInput({ input: '{}', inputFile: 'x' }, readFile)).rejects.toThrow(/either/)
    await expect(readOperationInput({ input: 'secret=oops' }, readFile)).rejects.toThrow(/valid JSON/)
  })

  it('refreshes before expiry then calls the operation with rotated access', async () => {
    const expiring = { ...credentials, expiresAt: 1_800_000_010_000 }
    const saved: StoredCredentials[] = []
    const fetch = vi.fn(async (input: URL | RequestInfo, init?: RequestInit) => {
      if (String(input).endsWith('/oauth/token')) {
        return Response.json({
          access_token: 'NEW-ACCESS', refresh_token: 'NEW-REFRESH', expires_in: 600,
          scope: 'clients:read programs:write', token_type: 'bearer',
          resource: `${origin}/api/agent/v1`,
        })
      }
      expect(new Headers(init?.headers).get('authorization')).toBe('Bearer NEW-ACCESS')
      return Response.json({ summary: 'Found one client.', data: { items: [] } })
    })

    const result = await callOperation('find_clients', { query: 'Alex' }, {
      origin,
      credentials: {
        assertAvailable: async () => undefined,
        get: async () => expiring,
        set: async (_account, value) => { saved.push(value) },
        delete: async () => true,
      },
      fetch,
      now: () => 1_800_000_000_000,
      randomBytes: (size) => new Uint8Array(size).fill(3),
    })

    expect(result).toEqual({ summary: 'Found one client.', data: { items: [] } })
    expect(saved[0]).toMatchObject({ accessToken: 'NEW-ACCESS', refreshToken: 'NEW-REFRESH' })
  })

  it('refreshes after one 401 and retries once', async () => {
    let operationCalls = 0
    const fetch = vi.fn(async (input: URL | RequestInfo) => {
      if (String(input).endsWith('/oauth/token')) {
        return Response.json({
          access_token: 'NEW-ACCESS', refresh_token: 'NEW-REFRESH', expires_in: 600,
          scope: 'clients:read programs:write', token_type: 'bearer',
          resource: `${origin}/api/agent/v1`,
        })
      }
      operationCalls += 1
      return operationCalls === 1
        ? Response.json({ error: 'invalid_token' }, { status: 401 })
        : Response.json({ summary: 'Recovered.', data: {} })
    })
    const set = vi.fn(async () => undefined)

    const result = await callOperation('find_clients', { query: 'Alex' }, {
      origin,
      credentials: { assertAvailable: async () => undefined, get: async () => credentials, set, delete: async () => true },
      fetch,
      now: () => 1_800_000_000_000,
      randomBytes: (size) => new Uint8Array(size).fill(4),
    })

    expect(result).toMatchObject({ summary: 'Recovered.' })
    expect(operationCalls).toBe(2)
    expect(set).toHaveBeenCalledOnce()
  })

  it('uses and refreshes staged credentials when old-grant recovery is blocked', async () => {
    const primary = {
      ...credentials,
      accessToken: 'OLD-ACCESS',
      clientId: 'old-client',
      refreshToken: 'OLD-REFRESH',
    }
    const staged = {
      ...credentials,
      accessToken: 'STAGED-ACCESS',
      refreshToken: 'STAGED-REFRESH',
      expiresAt: 1_800_000_010_000,
    }
    const accounts = new Map<string, StoredCredentials>([
      [origin, primary],
      [stagingAccount, staged],
    ])
    const writes: string[] = []
    const fetch = vi.fn(async (input: URL | RequestInfo, init?: RequestInit) => {
      if (String(input).endsWith('/oauth/revoke')) return new Response(null, { status: 503 })
      if (String(input).endsWith('/oauth/token')) {
        expect(String(init?.body)).toContain('refresh_token=STAGED-REFRESH')
        return Response.json({
          access_token: 'ROTATED-STAGED-ACCESS', refresh_token: 'ROTATED-STAGED-REFRESH', expires_in: 600,
          scope: 'clients:read programs:write', token_type: 'bearer', resource: `${origin}/api/agent/v1`,
        })
      }
      expect(new Headers(init?.headers).get('authorization')).toBe('Bearer ROTATED-STAGED-ACCESS')
      return Response.json({ summary: 'Used staged credentials.', data: {} })
    })

    const result = await callOperation('find_clients', { query: 'Alex' }, {
      origin,
      credentials: {
        assertAvailable: async () => undefined,
        get: async (account) => accounts.get(account) ?? null,
        set: async (account, value) => {
          writes.push(account)
          accounts.set(account, value)
        },
        delete: async (account) => accounts.delete(account),
      },
      fetch,
      now: () => 1_800_000_000_000,
      randomBytes: (size) => new Uint8Array(size).fill(4),
    })

    expect(result).toMatchObject({ summary: 'Used staged credentials.' })
    expect(writes).toEqual([stagingAccount])
    expect(accounts.get(stagingAccount)).toMatchObject({ refreshToken: 'ROTATED-STAGED-REFRESH' })
    expect(accounts.get(origin)).toEqual(primary)
  })

  it.each([stagingAccount, `reconnect:v1:fallback:${origin}`])(
    'keeps duplicate same-grant account %s synchronized through refresh and later cleanup',
    async (duplicateAccount) => {
      const expiring = {
        ...credentials,
        accessToken: 'PRE-ROTATION-ACCESS',
        refreshToken: 'PRE-ROTATION-REFRESH',
        expiresAt: 1_800_000_010_000,
      }
      const accounts = new Map<string, StoredCredentials>([
        [origin, expiring],
        [duplicateAccount, expiring],
      ])
      let cleanupFails = true
      let revocations = 0
      let operationCalls = 0
      const fetch = vi.fn(async (input: URL | RequestInfo, init?: RequestInit) => {
        if (String(input).endsWith('/oauth/revoke')) {
          revocations += 1
          return new Response(null, { status: 200 })
        }
        if (String(input).endsWith('/oauth/token')) {
          return Response.json({
            access_token: 'ROTATED-ACCESS', refresh_token: 'ROTATED-REFRESH', expires_in: 600,
            scope: 'clients:read programs:write', token_type: 'bearer', resource: `${origin}/api/agent/v1`,
          })
        }
        operationCalls += 1
        expect(new Headers(init?.headers).get('authorization')).toBe('Bearer ROTATED-ACCESS')
        return Response.json({ summary: 'Used current grant snapshot.', data: {} })
      })
      const dependencies = {
        origin,
        credentials: {
          assertAvailable: async () => undefined,
          get: async (account: string) => accounts.get(account) ?? null,
          set: async (account: string, value: StoredCredentials) => { accounts.set(account, value) },
          delete: async (account: string) => {
            if (account === duplicateAccount && cleanupFails) throw new Error('cleanup failed')
            return accounts.delete(account)
          },
        },
        fetch,
        now: () => 1_800_000_000_000,
        randomBytes: (size: number) => new Uint8Array(size).fill(4),
      }

      await callOperation('find_clients', { query: 'Alex' }, dependencies)

      const primaryAfterRefresh = accounts.get(origin)!
      const duplicateAfterRefresh = accounts.get(duplicateAccount)!
      expect(primaryAfterRefresh).toMatchObject({
        accessToken: 'ROTATED-ACCESS', refreshToken: 'ROTATED-REFRESH', tokenVersion: 1,
      })
      expect(duplicateAfterRefresh).toEqual(primaryAfterRefresh)
      expect(primaryAfterRefresh.grantId).toMatch(/^[A-Za-z0-9_-]+$/)

      cleanupFails = false
      await callOperation('find_clients', { query: 'Alex' }, dependencies)

      expect(revocations).toBe(0)
      expect(operationCalls).toBe(2)
      expect(accounts.has(duplicateAccount)).toBe(false)
      expect(accounts.get(origin)).toEqual(primaryAfterRefresh)
    },
  )

  it('repairs a primary snapshot after refresh survives only in staging', async () => {
    const expiring = {
      ...credentials,
      expiresAt: 1_800_000_010_000,
      grantId: Buffer.alloc(32, 6).toString('base64url'),
      tokenVersion: 0,
    }
    const accounts = new Map<string, StoredCredentials>([
      [origin, expiring],
      [stagingAccount, expiring],
    ])
    let primaryWriteFails = true
    let cleanupFails = true
    let refreshes = 0
    const fetch = vi.fn(async (input: URL | RequestInfo, init?: RequestInit) => {
      if (String(input).endsWith('/oauth/token')) {
        refreshes += 1
        return Response.json({
          access_token: 'ROTATED-ACCESS', refresh_token: 'ROTATED-REFRESH', expires_in: 600,
          scope: 'clients:read programs:write', token_type: 'bearer', resource: `${origin}/api/agent/v1`,
        })
      }
      expect(new Headers(init?.headers).get('authorization')).toBe('Bearer ROTATED-ACCESS')
      return Response.json({ summary: 'Used durable refresh.', data: {} })
    })
    const dependencies = {
      origin,
      credentials: {
        assertAvailable: async () => undefined,
        get: async (account: string) => accounts.get(account) ?? null,
        set: async (account: string, value: StoredCredentials) => {
          if (account === origin && primaryWriteFails) throw new Error('primary write failed')
          accounts.set(account, value)
        },
        delete: async (account: string) => {
          if (account === stagingAccount && cleanupFails) throw new Error('cleanup failed')
          return accounts.delete(account)
        },
      },
      fetch,
      now: () => 1_800_000_000_000,
      randomBytes: (size: number) => new Uint8Array(size).fill(4),
    }

    await callOperation('find_clients', { query: 'Alex' }, dependencies)

    expect(accounts.get(origin)).toEqual(expiring)
    expect(accounts.get(stagingAccount)).toMatchObject({
      accessToken: 'ROTATED-ACCESS', refreshToken: 'ROTATED-REFRESH', tokenVersion: 1,
    })

    primaryWriteFails = false
    cleanupFails = false
    await callOperation('find_clients', { query: 'Alex' }, dependencies)

    expect(refreshes).toBe(1)
    expect(accounts.has(stagingAccount)).toBe(false)
    expect(accounts.get(origin)).toMatchObject({
      accessToken: 'ROTATED-ACCESS', refreshToken: 'ROTATED-REFRESH', tokenVersion: 1,
    })
  })

  it('does not load or rotate credentials while reconnect holds the origin lock', async () => {
    const lockedOrigin = `https://call-lock-${process.pid}.example.test`
    const release = await nativeReconnectLock.acquire(lockedOrigin)
    const fetch = vi.fn()
    try {
      await expect(callOperation('find_clients', { query: 'Alex' }, {
        origin: lockedOrigin,
        credentials: {
          assertAvailable: async () => undefined,
          get: async () => ({ ...credentials, origin: lockedOrigin }),
          set: async () => undefined,
          delete: async () => true,
        },
        fetch,
        now: () => 1_800_000_000_000,
        randomBytes: (size) => new Uint8Array(size),
        reconnectLock: nativeReconnectLock,
      })).rejects.toThrow(/already in progress/i)
    } finally {
      await release()
    }
    expect(fetch).not.toHaveBeenCalled()
  })

  it('keeps one idempotency key across one transport retry', async () => {
    const keys: string[] = []
    const fetch = vi.fn(async (_input: URL | RequestInfo, init?: RequestInit) => {
      keys.push((JSON.parse(String(init?.body)) as { idempotencyKey: string }).idempotencyKey)
      if (keys.length === 1) throw new TypeError('socket reset')
      return Response.json({ summary: 'Draft saved.', data: { id: 'draft-1' } })
    })

    await callOperation('save_program_draft', { title: 'Plan', content: 'x' }, {
      origin,
      credentials: { assertAvailable: async () => undefined, get: async () => credentials, set: async () => undefined, delete: async () => true },
      fetch,
      now: () => 1_800_000_000_000,
      randomBytes: (size) => new Uint8Array(size).fill(5),
    })

    expect(fetch).toHaveBeenCalledTimes(2)
    expect(keys[0]).toMatch(/^[A-Za-z0-9_-]+$/)
    expect(keys[1]).toBe(keys[0])
  })

  it.each([
    [307, 'https://evil.example.test/capture'],
    [308, `${origin}/capture`],
  ])('refuses operation redirect %i without resending bearer token or body', async (status, location) => {
    const bodies: string[] = []
    const fetch = vi.fn(async (_input: URL | RequestInfo, init?: RequestInit) => {
      bodies.push(String(init?.body))
      return new Response(null, { status, headers: { location } })
    })

    await expect(callOperation('find_clients', { query: 'Alex' }, {
      origin,
      credentials: { assertAvailable: async () => undefined, get: async () => credentials, set: async () => undefined, delete: async () => true },
      fetch,
      now: () => 1_800_000_000_000,
      randomBytes: (size) => new Uint8Array(size),
    })).rejects.toThrow(/redirect/i)
    expect(fetch).toHaveBeenCalledOnce()
    expect(fetch.mock.calls[0][1]).toMatchObject({ redirect: 'manual' })
    expect(new Headers(fetch.mock.calls[0][1]?.headers).get('authorization')).toBe('Bearer ACCESS-SECRET')
    expect(bodies).toEqual(['{"query":"Alex"}'])
  })

  it('throws operation errors for a nonzero CLI exit and never includes stored tokens', async () => {
    const envelope = {
      error: {
        code: 'confirmation_required',
        message: 'Coach confirmation is required',
        retryable: false,
        details: {
          confirmationId: '11111111-1111-4111-8111-111111111111',
          confirmationUrl: `${origin}/confirm/11111111-1111-4111-8111-111111111111`,
          preview: { summary: 'Move session.' },
        },
      },
    }
    const fetch = vi.fn(async () => Response.json({
      error: { code: 'validation_failed', message: 'Query is invalid.', retryable: false },
    }, { status: 422 }))

    await expect(callOperation('find_clients', { query: '' }, {
      origin,
      credentials: { assertAvailable: async () => undefined, get: async () => credentials, set: async () => undefined, delete: async () => true },
      fetch,
      now: () => 1_800_000_000_000,
      randomBytes: (size) => new Uint8Array(size),
    })).rejects.toMatchObject({ exitCode: 1, message: 'validation_failed: Query is invalid.' })
    expect(JSON.stringify(fetch.mock.calls)).not.toContain('REFRESH-SECRET')

    const confirmationFetch = vi.fn(async () => Response.json(envelope, { status: 409 }))
    const caught = await callOperation('reschedule_session', {
      sessionId: 'session-1', expectedVersion: '1', scheduledDate: '2026-02-01',
    }, {
      origin,
      credentials: { assertAvailable: async () => undefined, get: async () => credentials, set: async () => undefined, delete: async () => true },
      fetch: confirmationFetch,
      now: () => 1_800_000_000_000,
      randomBytes: (size) => new Uint8Array(size).fill(7),
    }).catch((error: unknown) => error)
    expect(caught).toBeInstanceOf(OperationError)
    expect(caught.envelope).toEqual(envelope)
    expect(caught.idempotencyKey).toBe(Buffer.alloc(24, 7).toString('base64url'))
    expect(caught).not.toHaveProperty('input')
  })

  it('supports a CLI confirmation-first call and explicit identical retry controls', async () => {
    const confirmationId = '11111111-1111-4111-8111-111111111111'
    const requestBodies: Array<Record<string, unknown>> = []
    const server = createServer((request, response) => {
      const chunks: Buffer[] = []
      request.on('data', (chunk: Buffer) => chunks.push(chunk))
      request.on('end', () => {
        expect(request.method).toBe('POST')
        expect(request.url).toBe('/api/agent/v1/operations/reschedule_session')
        expect(request.headers.authorization).toBe('Bearer ACCESS-SECRET')
        const body = JSON.parse(Buffer.concat(chunks).toString('utf8')) as Record<string, unknown>
        requestBodies.push(body)
        response.setHeader('content-type', 'application/json')
        if (requestBodies.length === 1) {
          response.statusCode = 409
          response.end(JSON.stringify({
            error: {
              code: 'confirmation_required', message: 'Coach confirmation is required', retryable: false,
              details: {
                confirmationId,
                confirmationUrl: `${localOrigin}/confirm/${confirmationId}`,
                preview: { summary: 'Move session.' },
              },
            },
          }))
          return
        }
        response.end(JSON.stringify({ summary: 'Session rescheduled.', data: { sessionId: 'session-1' } }))
      })
    })
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject)
      server.listen(0, '127.0.0.1', resolve)
    })
    const port = (server.address() as AddressInfo).port
    const localOrigin = `http://127.0.0.1:${port}`
    const localCredentials = {
      ...credentials,
      origin: localOrigin,
      issuer: localOrigin,
      tokenEndpoint: `${localOrigin}/oauth/token`,
    }
    const confirmationUrl = `${localOrigin}/confirm/${confirmationId}`
    let output = ''
    let error = ''
    const dependencies: CliDependencies = {
      originEnvironment: undefined,
      fetch: globalThis.fetch,
      browserOpen: vi.fn(), callbackServer: { start: vi.fn() },
      credentials: { assertAvailable: async () => undefined, get: async () => localCredentials, set: async () => undefined, delete: async () => true },
      now: () => 1_800_000_000_000,
      randomBytes: (size) => new Uint8Array(size).fill(8), readFile: vi.fn(),
      stdout: (text) => { output += text }, stderr: (text) => { error += text },
    }
    const base = { sessionId: 'session-1', expectedVersion: '1', scheduledDate: '2026-02-01' }

    try {
      const firstExit = await runCli([
        'node', 'athlendra', '--origin', localOrigin, 'call', 'reschedule_session',
        '--input', JSON.stringify(base),
      ], dependencies)
      const generatedKey = requestBodies[0].idempotencyKey as string
      expect(firstExit).toBe(1)
      expect(error).toContain(confirmationUrl)
      expect(error).toContain(generatedKey)
      expect(error).toContain(confirmationId)

      error = ''
      const retryInput = { ...base, idempotencyKey: generatedKey, confirmationId }
      const secondExit = await runCli([
        'node', 'athlendra', '--origin', localOrigin, 'call', 'reschedule_session',
        '--input', JSON.stringify(retryInput),
      ], dependencies)
      expect(secondExit).toBe(0)
      expect(requestBodies[1]).toEqual({ ...requestBodies[0], confirmationId })
      expect(output).toContain('Session rescheduled.')
      expect(error).toBe('')
    } finally {
      await new Promise<void>((resolve, reject) => server.close((caught) => caught ? reject(caught) : resolve()))
    }
  })

  it('prints an exact stable JSON error envelope, exits nonzero, and exposes generated retry key separately', async () => {
    const envelope = {
      error: {
        retryable: false,
        message: 'Coach confirmation is required',
        details: {
          preview: { z: 2, a: 1 },
          confirmationUrl: `${origin}/confirm/11111111-1111-4111-8111-111111111111`,
          confirmationId: '11111111-1111-4111-8111-111111111111',
        },
        code: 'confirmation_required',
      },
    }
    let output = ''
    let error = ''
    const dependencies: CliDependencies = {
      originEnvironment: undefined,
      fetch: vi.fn(async () => Response.json(envelope, { status: 409 })),
      browserOpen: vi.fn(), callbackServer: { start: vi.fn() },
      credentials: { assertAvailable: async () => undefined, get: async () => credentials, set: async () => undefined, delete: async () => true },
      now: () => 1_800_000_000_000,
      randomBytes: (size) => new Uint8Array(size).fill(6), readFile: vi.fn(),
      stdout: (text) => { output += text }, stderr: (text) => { error += text },
    }

    const exit = await runCli([
      'node', 'athlendra', '--origin', origin, 'call', 'reschedule_session', '--json',
      '--input', '{"sessionId":"session-1","expectedVersion":"1","scheduledDate":"2026-02-01"}',
    ], dependencies)

    expect(exit).toBe(1)
    expect(output).toBe(`${JSON.stringify({
      error: {
        code: 'confirmation_required',
        details: {
          confirmationId: '11111111-1111-4111-8111-111111111111',
          confirmationUrl: `${origin}/confirm/11111111-1111-4111-8111-111111111111`,
          preview: { a: 1, z: 2 },
        },
        message: 'Coach confirmation is required', retryable: false,
      },
    })}\n`)
    expect(error).toContain(Buffer.alloc(24, 6).toString('base64url'))
    expect(error).not.toContain('session-1')
  })
})
import { createServer } from 'node:http'
import type { AddressInfo } from 'node:net'
