import { createHash } from 'node:crypto'
import { describe, expect, it, vi } from 'vitest'
import {
  connect,
  DEFAULT_READ_SCOPES,
  FULL_SCOPES,
  loadCredentials,
  logout,
  revokeCredentials,
  refreshCredentials,
  resolveOrigin,
  type AuthDependencies,
  type LoadedCredentials,
  type StoredCredentials,
} from '../src/auth'
import { startLoopbackCallbackServer } from '../src/callback-server'
import { nativeReconnectLock } from '../src/reconnect-lock'

const origin = 'https://api.athlendra.test'
const issuer = 'https://app.athlendra.test'
const stagingAccount = `reconnect:v1:${origin}`
const fallbackStagingAccount = `reconnect:v1:fallback:${origin}`

function storedCredential(overrides: Partial<StoredCredentials> = {}): StoredCredentials {
  return {
    accessToken: 'old-access',
    clientId: 'old-client',
    expiresAt: 1_900_000_000_000,
    origin,
    redirectUri: 'http://127.0.0.1:45678/oauth/callback',
    refreshToken: 'old-refresh',
    scopes: ['clients:read'],
    tokenEndpoint: `${origin}/oauth/token`,
    ...overrides,
  }
}

function loadedCredential(
  credentials: StoredCredentials,
  accounts: string[] = [origin],
  account = accounts[0],
): LoadedCredentials {
  return {
    account,
    accounts,
    credentials: { ...credentials, issuer: credentials.issuer ?? credentials.origin },
  }
}

function json(value: unknown, status = 200): Response {
  return Response.json(value, { status })
}

function fakeFlow(
  overrides: Partial<AuthDependencies> = {},
  supportedScopes: readonly string[] = FULL_SCOPES,
) {
  const requests: Request[] = []
  const stored: StoredCredentials[] = []
  let browserUrl = ''
  const stateBytes = new Uint8Array(32).fill(1)
  const verifierBytes = new Uint8Array(64).fill(2)
  const deps: AuthDependencies = {
    fetch: vi.fn(async (input, init) => {
      const request = new Request(input, init)
      requests.push(request)
      if (request.url.endsWith('/.well-known/oauth-protected-resource/api/agent/v1')) {
        return json({
          resource: `${origin}/api/agent/v1`,
          authorization_servers: [issuer],
          scopes_supported: supportedScopes,
        })
      }
      if (request.url.endsWith('/.well-known/oauth-authorization-server')) {
        return json({
          issuer,
          authorization_endpoint: `${issuer}/oauth/authorize`,
          token_endpoint: `${issuer}/oauth/token`,
          registration_endpoint: `${issuer}/oauth/register`,
          code_challenge_methods_supported: ['S256'],
        })
      }
      if (request.url.endsWith('/oauth/register')) {
        return json({ client_id: 'dynamic-client' }, 201)
      }
      if (request.url.endsWith('/oauth/token')) {
        return json({
          access_token: 'ACCESS-SECRET',
          refresh_token: 'REFRESH-SECRET',
          expires_in: 3600,
          scope: DEFAULT_READ_SCOPES.join(' '),
          token_type: 'bearer',
          resource: `${origin}/api/agent/v1`,
        })
      }
      if (request.url.endsWith('/oauth/revoke')) return new Response(null, { status: 200 })
      throw new Error(`Unexpected request: ${request.url}`)
    }),
    browserOpen: vi.fn(async (url) => {
      browserUrl = url
    }),
    callbackServer: {
      start: vi.fn(async () => ({
        redirectUri: 'http://127.0.0.1:45678/oauth/callback',
        waitForCallback: async () => {
          const authorization = new URL(browserUrl)
          return {
            code: 'authorization-code',
            state: authorization.searchParams.get('state')!,
            issuer,
          }
        },
        close: vi.fn(async () => undefined),
      })),
    },
    credentials: {
      assertAvailable: vi.fn(async () => undefined),
      get: vi.fn(async () => null),
      set: vi.fn(async (_account, credentials) => { stored.push(credentials) }),
      delete: vi.fn(async () => true),
    },
    now: () => 1_800_000_000_000,
    randomBytes: vi.fn((size) => size === 32 ? stateBytes : verifierBytes),
    ...overrides,
  }
  return { deps, requests, stored, getBrowserUrl: () => browserUrl, stateBytes, verifierBytes }
}

describe('CLI OAuth', () => {
  it('discovers endpoints, registers exact loopback redirect, and uses random S256 PKCE', async () => {
    const flow = fakeFlow()

    const result = await connect({ origin }, flow.deps)

    const registration = flow.requests.find((request) => request.url.endsWith('/oauth/register'))!
    expect(await registration.json()).toEqual({
      client_name: 'Athlendra CLI',
      grant_types: ['authorization_code', 'refresh_token'],
      redirect_uris: ['http://127.0.0.1:45678/oauth/callback'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none',
    })
    const authorization = new URL(flow.getBrowserUrl())
    const expectedState = Buffer.from(flow.stateBytes).toString('base64url')
    const verifier = Buffer.from(flow.verifierBytes).toString('base64url')
    const expectedChallenge = createHash('sha256').update(verifier).digest('base64url')
    expect(flow.requests[1].url).toBe(`${issuer}/.well-known/oauth-authorization-server`)
    expect(authorization.origin + authorization.pathname).toBe(`${issuer}/oauth/authorize`)
    expect(Object.fromEntries(authorization.searchParams)).toMatchObject({
      client_id: 'dynamic-client',
      code_challenge: expectedChallenge,
      code_challenge_method: 'S256',
      redirect_uri: 'http://127.0.0.1:45678/oauth/callback',
      resource: `${origin}/api/agent/v1`,
      response_type: 'code',
      scope: DEFAULT_READ_SCOPES.join(' '),
      state: expectedState,
    })
    const tokenRequest = flow.requests.find((request) => request.url.endsWith('/oauth/token'))!
    expect(tokenRequest.url).toBe(`${issuer}/oauth/token`)
    expect(await tokenRequest.text()).toContain(`code_verifier=${encodeURIComponent(verifier)}`)
    expect(tokenRequest.redirect).toBe('manual')
    expect(registration.redirect).toBe('manual')
    expect(result.scopes).toEqual(DEFAULT_READ_SCOPES)
    expect(flow.stored).toHaveLength(2)
    expect(flow.stored[1]).toMatchObject({
      accessToken: 'ACCESS-SECRET',
      refreshToken: 'REFRESH-SECRET',
      expiresAt: 1_800_003_600_000,
      origin,
      issuer,
      redirectUri: 'http://127.0.0.1:45678/oauth/callback',
    })
  })

  it.each([
    ['none', []],
    ['multiple', [issuer, 'https://other.athlendra.test']],
    ['insecure', ['http://app.athlendra.test']],
    ['non-origin', [`${issuer}/oauth`]],
  ])('rejects %s authorization server metadata before issuer discovery', async (_case, authorizationServers) => {
    const flow = fakeFlow()
    const normalFetch = flow.deps.fetch
    flow.deps.fetch = vi.fn(async (input, init) => {
      if (String(input).endsWith('/.well-known/oauth-protected-resource/api/agent/v1')) {
        return json({
          resource: `${origin}/api/agent/v1`,
          authorization_servers: authorizationServers,
          scopes_supported: FULL_SCOPES,
        })
      }
      return normalFetch(input, init)
    })

    await expect(connect({ origin }, flow.deps)).rejects.toThrow(/authorization server/i)
    expect(flow.getBrowserUrl()).toBe('')
    expect(flow.requests).toHaveLength(0)
  })

  it.each([
    ['state', { code: 'code', state: 'wrong', issuer }],
    ['issuer', { code: 'code', state: Buffer.alloc(32, 1).toString('base64url'), issuer: 'https://evil.test' }],
  ])('rejects callback %s mismatch before code exchange', async (_case, callback) => {
    const flow = fakeFlow({
      callbackServer: {
        start: vi.fn(async () => ({
          redirectUri: 'http://127.0.0.1:45678/oauth/callback',
          waitForCallback: async () => callback,
          close: vi.fn(async () => undefined),
        })),
      },
    })

    await expect(connect({ origin }, flow.deps)).rejects.toThrow(/callback/i)
    expect(flow.requests.filter((request) => request.url.endsWith('/oauth/token'))).toHaveLength(0)
    expect(flow.stored).toHaveLength(0)
  })

  it.each([
    ['cross-origin DCR 307', '/oauth/register', 307, 'https://evil.example.test/capture'],
    ['same-origin token 308', '/oauth/token', 308, `${issuer}/capture`],
  ])('refuses %s without resending registration or code secrets', async (_case, path, status, location) => {
    const flow = fakeFlow()
    const normalFetch = flow.deps.fetch
    const requests: Request[] = []
    flow.deps.fetch = vi.fn(async (input, init) => {
      const request = new Request(input, init)
      requests.push(request)
      if (request.url.endsWith(path)) return new Response(null, { status, headers: { location } })
      return normalFetch(input, init)
    })

    await expect(connect({ origin }, flow.deps)).rejects.toThrow(/redirect/i)
    const secretPosts = requests.filter((request) => request.url.endsWith(path))
    expect(secretPosts).toHaveLength(1)
    expect(secretPosts[0].redirect).toBe('manual')
    expect(requests.some((request) => request.url.endsWith('/capture'))).toBe(false)
  })

  it.each([
    ['no writes', DEFAULT_READ_SCOPES],
    ['notes write enabled', [...DEFAULT_READ_SCOPES, 'notes:write']],
    ['program and session writes enabled', [
      ...DEFAULT_READ_SCOPES, 'programs:write', 'sessions:write',
    ]],
    ['client and exercise writes enabled', [
      ...DEFAULT_READ_SCOPES, 'clients:write', 'exercises:write',
    ]],
  ])('builds full profile from advertised scopes when %s', async (_case, advertised) => {
    const full = fakeFlow({}, advertised)

    await connect({ origin, profile: 'full' }, full.deps)

    expect(new URL(full.getBrowserUrl()).searchParams.get('scope')).toBe(advertised.join(' '))
  })

  it('uses fixed read or explicit least-privilege scopes and rejects unavailable scopes', async () => {
    const read = fakeFlow({}, DEFAULT_READ_SCOPES)
    await connect({ origin, profile: 'read' }, read.deps)
    expect(new URL(read.getBrowserUrl()).searchParams.get('scope'))
      .toBe(DEFAULT_READ_SCOPES.join(' '))

    const narrow = fakeFlow()
    await connect({ origin, scopes: ['clients:read', 'sessions:read'] }, narrow.deps)
    expect(new URL(narrow.getBrowserUrl()).searchParams.get('scope')).toBe('clients:read sessions:read')

    const unavailable = fakeFlow({}, DEFAULT_READ_SCOPES)
    await expect(connect({ origin, scopes: ['notes:write'] }, unavailable.deps))
      .rejects.toThrow('Unsupported scope: notes:write')
    expect(unavailable.getBrowserUrl()).toBe('')
    expect(unavailable.requests.some((request) => request.url.endsWith('/oauth/register'))).toBe(false)

    await expect(connect({ origin, scopes: ['admin:all'] }, fakeFlow().deps))
      .rejects.toThrow('Unsupported scope: admin:all')
  })

  it('reconnects with fresh state and replaces stored credentials', async () => {
    let byte = 0
    const flow = fakeFlow({ randomBytes: vi.fn((size) => new Uint8Array(size).fill(++byte)) })

    await connect({ origin }, flow.deps)
    const firstState = new URL(flow.getBrowserUrl()).searchParams.get('state')
    await connect({ origin }, flow.deps)
    const secondState = new URL(flow.getBrowserUrl()).searchParams.get('state')

    expect(secondState).not.toBe(firstState)
    expect(flow.stored).toHaveLength(4)
    expect(flow.stored[3].grantId).not.toBe(flow.stored[1].grantId)
  })

  it('rotates refresh credentials and keeps the new refresh token', async () => {
    const current: StoredCredentials = {
      accessToken: 'old-access',
      clientId: 'dynamic-client',
      expiresAt: 1,
      origin,
      issuer,
      redirectUri: 'http://127.0.0.1:45678/oauth/callback',
      refreshToken: 'old-refresh',
      scopes: ['clients:read'],
      tokenEndpoint: `${issuer}/oauth/token`,
    }
    const saved: StoredCredentials[] = []
    const deps = fakeFlow({
      fetch: vi.fn(async (input, init) => {
        expect(String(input)).toBe(`${issuer}/oauth/token`)
        expect(String(init?.body)).toContain('refresh_token=old-refresh')
        expect(String(init?.body)).toContain(`resource=${encodeURIComponent(`${origin}/api/agent/v1`)}`)
        return json({
          access_token: 'new-access', refresh_token: 'new-refresh', expires_in: 600,
          scope: 'clients:read', token_type: 'bearer', resource: `${origin}/api/agent/v1`,
        })
      }),
      credentials: {
        assertAvailable: async () => undefined,
        get: async () => current,
        set: async (_account, value) => { saved.push(value) },
        delete: async () => true,
      },
    }).deps

    const rotated = await refreshCredentials(loadedCredential(current), deps)

    expect(rotated).toMatchObject({
      account: origin,
      accounts: [origin],
      credentials: { accessToken: 'new-access', refreshToken: 'new-refresh', tokenVersion: 1 },
    })
    expect(saved).toEqual([rotated.credentials])
  })

  it('normalizes a legacy stored credential issuer to its API origin', async () => {
    const legacy = storedCredential()

    const loaded = await loadCredentials(origin, {
      fetch: vi.fn(),
      credentials: {
        assertAvailable: async () => undefined,
        get: async (account) => account === origin ? legacy : null,
        set: async () => undefined,
        delete: async () => true,
      },
      now: Date.now,
      reconnectLock: { acquire: async () => async () => undefined },
    })

    expect(loaded?.credentials).toMatchObject({ origin, issuer: origin })
  })

  it.each([
    {
      name: 'primary fails and staging succeeds',
      accounts: [origin, stagingAccount],
      failed: [origin],
      selected: stagingAccount,
    },
    {
      name: 'primary and staging fail and fallback succeeds',
      accounts: [origin, stagingAccount, fallbackStagingAccount],
      failed: [origin, stagingAccount],
      selected: fallbackStagingAccount,
    },
  ])('stores a rotated grant when $name', async ({ accounts: tracked, failed, selected }) => {
    const grantId = Buffer.alloc(32, 7).toString('base64url')
    const current = storedCredential({ grantId, expiresAt: 1, tokenVersion: 0 })
    const records = new Map(tracked.map((account) => [account, current]))
    const attempts: string[] = []
    const deps = fakeFlow({
      fetch: vi.fn(async () => json({
        access_token: 'new-access', refresh_token: 'new-refresh', expires_in: 600,
        scope: 'clients:read', token_type: 'bearer', resource: `${origin}/api/agent/v1`,
      })),
      credentials: {
        assertAvailable: async () => undefined,
        get: async (account) => records.get(account) ?? null,
        set: async (account, value) => {
          attempts.push(account)
          if (failed.includes(account)) throw new Error('keyring write failed')
          records.set(account, value)
        },
        delete: async () => true,
      },
    }).deps

    const rotated = await refreshCredentials(loadedCredential(current, tracked), deps)

    expect(attempts).toEqual(tracked)
    expect(rotated.account).toBe(selected)
    expect(rotated.accounts).toEqual(tracked)
    expect(rotated.credentials).toMatchObject({
      accessToken: 'new-access', refreshToken: 'new-refresh', grantId, tokenVersion: 1,
    })
    expect(records.get(selected)).toEqual(rotated.credentials)
  })

  it('reports an actionable error without tokens when every rotated snapshot write fails', async () => {
    const current = storedCredential({ expiresAt: 1 })
    const records = new Map([[origin, current], [stagingAccount, current]])
    const deps = fakeFlow({
      fetch: vi.fn(async () => json({
        access_token: 'new-access-secret', refresh_token: 'new-refresh-secret', expires_in: 600,
        scope: 'clients:read', token_type: 'bearer', resource: `${origin}/api/agent/v1`,
      })),
      credentials: {
        assertAvailable: async () => undefined,
        get: async (account) => records.get(account) ?? null,
        set: async () => { throw new Error('keyring write failed') },
        delete: async () => true,
      },
    }).deps

    const caught = await refreshCredentials(
      loadedCredential(current, [origin, stagingAccount]),
      deps,
    ).catch((error: unknown) => error)

    expect(caught).toMatchObject({ message: expect.stringMatching(/rotated.*keyring.*revoke.*reconnect/i) })
    expect(caught.message).not.toContain('new-access-secret')
    expect(caught.message).not.toContain('new-refresh-secret')
    expect(records.get(origin)).toEqual(current)
    expect(records.get(stagingAccount)).toEqual(current)
  })

  it('never writes a rotated snapshot over a tracked account from another grant', async () => {
    const current = storedCredential({ grantId: Buffer.alloc(32, 3).toString('base64url'), expiresAt: 1 })
    const unrelated = storedCredential({
      grantId: Buffer.alloc(32, 4).toString('base64url'),
      refreshToken: 'unrelated-refresh',
    })
    const records = new Map([[origin, current], [stagingAccount, unrelated]])
    const writes: string[] = []
    const deps = fakeFlow({
      fetch: vi.fn(async () => json({
        access_token: 'new-access', refresh_token: 'new-refresh', expires_in: 600,
        scope: 'clients:read', token_type: 'bearer', resource: `${origin}/api/agent/v1`,
      })),
      credentials: {
        assertAvailable: async () => undefined,
        get: async (account) => records.get(account) ?? null,
        set: async (account, value) => {
          writes.push(account)
          records.set(account, value)
        },
        delete: async () => true,
      },
    }).deps

    const rotated = await refreshCredentials(
      loadedCredential(current, [origin, stagingAccount]),
      deps,
    )

    expect(writes).toEqual([origin])
    expect(rotated.accounts).toEqual([origin])
    expect(records.get(stagingAccount)).toEqual(unrelated)
  })

  it('never sends a refresh token to an endpoint outside its credential issuer', async () => {
    const current: StoredCredentials = {
      accessToken: 'old-access',
      clientId: 'dynamic-client',
      expiresAt: 1,
      origin,
      redirectUri: 'http://127.0.0.1:45678/oauth/callback',
      refreshToken: 'old-refresh',
      scopes: ['clients:read'],
      tokenEndpoint: 'https://evil.example.test/oauth/token',
    }
    const fetch = vi.fn()

    await expect(refreshCredentials(loadedCredential(current), {
      fetch,
      credentials: fakeFlow().deps.credentials,
      now: () => 1_800_000_000_000,
    })).rejects.toThrow(/token endpoint.*issuer/i)
    expect(fetch).not.toHaveBeenCalled()
  })

  it.each([
    [307, 'https://evil.example.test/capture'],
    [308, `${origin}/capture`],
  ])('refuses refresh redirect %i without resending the refresh token', async (status, location) => {
    const current: StoredCredentials = {
      accessToken: 'old-access', clientId: 'dynamic-client', expiresAt: 1, origin,
      redirectUri: 'http://127.0.0.1:45678/oauth/callback', refreshToken: 'old-refresh',
      scopes: ['clients:read'], tokenEndpoint: `${origin}/oauth/token`,
    }
    const fetch = vi.fn(async () => new Response(null, { status, headers: { location } }))
    const credentials = fakeFlow().deps.credentials
    credentials.get = vi.fn(async () => current)

    await expect(refreshCredentials(loadedCredential(current), {
      fetch, credentials, now: () => 1_800_000_000_000,
    })).rejects.toThrow(/redirect/i)
    expect(fetch).toHaveBeenCalledOnce()
    expect(fetch.mock.calls[0][1]).toMatchObject({ redirect: 'manual' })
    expect(String(fetch.mock.calls[0][1]?.body)).toContain('refresh_token=old-refresh')
  })

  it.each([
    [307, 'https://evil.example.test/capture'],
    [308, `${origin}/capture`],
  ])('refuses revoke redirect %i without resending or deleting credentials', async (status, location) => {
    const current: StoredCredentials = {
      accessToken: 'old-access', clientId: 'dynamic-client', expiresAt: 1, origin,
      redirectUri: 'http://127.0.0.1:45678/oauth/callback', refreshToken: 'old-refresh',
      scopes: ['clients:read'], tokenEndpoint: `${origin}/oauth/token`,
    }
    const fetch = vi.fn(async () => new Response(null, { status, headers: { location } }))
    const remove = vi.fn(async () => true)
    const store = {
      assertAvailable: async () => undefined,
      get: async () => current,
      set: async () => undefined,
      delete: remove,
    }

    await expect(logout(origin, { fetch, credentials: store, now: Date.now })).rejects.toThrow(/redirect/i)
    expect(fetch).toHaveBeenCalledOnce()
    expect(fetch.mock.calls[0][1]).toMatchObject({ redirect: 'manual' })
    expect(String(fetch.mock.calls[0][1]?.body)).toContain('token=old-refresh')
    expect(remove).not.toHaveBeenCalled()
  })

  it('stages new credentials before revoking and replacing the prior grant', async () => {
    const previous = storedCredential({
      clientId: 'dynamic-client',
      grantId: Buffer.alloc(32, 9).toString('base64url'),
    })
    const events: string[] = []
    const flow = fakeFlow()
    const normalFetch = flow.deps.fetch
    flow.deps.fetch = vi.fn(async (input, init) => {
      if (String(input).endsWith('/oauth/revoke')) {
        events.push(`revoke:${String(init?.body)}`)
        return new Response(null, { status: 200 })
      }
      return normalFetch(input, init)
    })
    flow.deps.credentials.get = vi.fn(async (account) => account === origin ? previous : null)
    flow.deps.credentials.set = vi.fn(async (account) => { events.push(`set:${account}`) })
    flow.deps.credentials.delete = vi.fn(async (account) => {
      events.push(`delete:${account}`)
      return true
    })

    await connect({ origin }, flow.deps)

    expect(events[0]).toBe(`set:${stagingAccount}`)
    expect(events[1]).toContain('revoke:')
    expect(events[1]).toContain('client_id=dynamic-client')
    expect(events[1]).toContain('token=old-refresh')
    expect(events[1]).toContain('token_type_hint=refresh_token')
    expect(events[2]).toBe(`set:${origin}`)
    expect(events[3]).toBe(`delete:${stagingAccount}`)
  })

  it('retains both usable grants when prior revocation fails after new issuance', async () => {
    const previous = storedCredential()
    const accounts = new Map<string, StoredCredentials>([[origin, previous]])
    const flow = fakeFlow()
    const normalFetch = flow.deps.fetch
    flow.deps.fetch = vi.fn(async (input, init) => String(input).endsWith('/oauth/revoke')
      ? new Response(null, { status: 503 })
      : normalFetch(input, init))
    flow.deps.credentials.get = vi.fn(async (account) => accounts.get(account) ?? null)
    flow.deps.credentials.set = vi.fn(async (account, value) => { accounts.set(account, value) })
    flow.deps.credentials.delete = vi.fn(async (account) => accounts.delete(account))

    await expect(connect({ origin }, flow.deps)).rejects.toThrow(/recovery.*revocation.*503/i)
    expect(accounts.get(origin)).toEqual(previous)
    expect(accounts.get(stagingAccount)).toMatchObject({ refreshToken: 'REFRESH-SECRET' })
    expect(flow.deps.credentials.set).toHaveBeenCalledOnce()
    expect(flow.deps.credentials.delete).not.toHaveBeenCalled()
  })

  it('revokes the new grant when staging it fails', async () => {
    const previous = storedCredential()
    const accounts = new Map<string, StoredCredentials>([[origin, previous]])
    const revokedTokens: string[] = []
    const flow = fakeFlow()
    const normalFetch = flow.deps.fetch
    flow.deps.fetch = vi.fn(async (input, init) => {
      if (String(input).endsWith('/oauth/revoke')) {
        revokedTokens.push(new URLSearchParams(String(init?.body)).get('token')!)
        return new Response(null, { status: 200 })
      }
      return normalFetch(input, init)
    })
    flow.deps.credentials = {
      assertAvailable: async () => undefined,
      get: async (account) => accounts.get(account) ?? null,
      set: async (account, value) => {
        if (account === stagingAccount) throw new Error('keyring write failed')
        accounts.set(account, value)
      },
      delete: async (account) => accounts.delete(account),
    }

    await expect(connect({ origin }, flow.deps)).rejects.toThrow(/new grant.*revoked/i)
    expect(revokedTokens).toEqual(['REFRESH-SECRET'])
    expect(accounts.get(origin)).toEqual(previous)
    expect(accounts.has(stagingAccount)).toBe(false)
  })

  it('stores the new grant in a fallback recovery account when staging and compensation fail', async () => {
    const previous = storedCredential()
    const accounts = new Map<string, StoredCredentials>([[origin, previous]])
    const flow = fakeFlow()
    const normalFetch = flow.deps.fetch
    flow.deps.fetch = vi.fn(async (input, init) => String(input).endsWith('/oauth/revoke')
      ? new Response(null, { status: 503 })
      : normalFetch(input, init))
    flow.deps.credentials = {
      assertAvailable: async () => undefined,
      get: async (account) => accounts.get(account) ?? null,
      set: async (account, value) => {
        if (account === stagingAccount) throw new Error('primary staging write failed')
        accounts.set(account, value)
      },
      delete: async (account) => accounts.delete(account),
    }

    await expect(connect({ origin }, flow.deps)).rejects.toThrow(/fallback recovery account/i)
    expect(accounts.get(origin)).toEqual(previous)
    expect(accounts.get(fallbackStagingAccount)).toMatchObject({ refreshToken: 'REFRESH-SECRET' })
  })

  it('preserves prior credentials and identifies the client when storage and compensation both fail', async () => {
    const previous = storedCredential()
    const accounts = new Map<string, StoredCredentials>([[origin, previous]])
    const flow = fakeFlow()
    const normalFetch = flow.deps.fetch
    flow.deps.fetch = vi.fn(async (input, init) => String(input).endsWith('/oauth/revoke')
      ? new Response(null, { status: 503 })
      : normalFetch(input, init))
    flow.deps.credentials = {
      assertAvailable: async () => undefined,
      get: async (account) => accounts.get(account) ?? null,
      set: async () => { throw new Error('keyring unavailable') },
      delete: async (account) => accounts.delete(account),
    }

    const caught = await connect({ origin }, flow.deps).catch((error: unknown) => error)
    expect(caught).toMatchObject({ message: expect.stringMatching(/dynamic-client.*revoke.*before reconnecting/i) })
    expect(caught.message).not.toContain('ACCESS-SECRET')
    expect(caught.message).not.toContain('REFRESH-SECRET')
    expect(accounts).toEqual(new Map([[origin, previous]]))
  })

  it('holds one reconnect lock across OAuth and credential promotion', async () => {
    let held = false
    const lock = {
      async acquire() {
        if (held) throw new Error('Reconnect already in progress.')
        held = true
        return async () => { held = false }
      },
    }
    let releaseCallback!: () => void
    const first = fakeFlow({
      callbackServer: {
        start: vi.fn(async () => ({
          redirectUri: 'http://127.0.0.1:45678/oauth/callback',
          waitForCallback: () => new Promise((resolve) => {
            releaseCallback = () => resolve({
              code: 'authorization-code',
              state: Buffer.alloc(32, 1).toString('base64url'),
              issuer,
            })
          }),
          close: vi.fn(async () => undefined),
        })),
      },
    })
    const second = fakeFlow()
    Object.assign(first.deps, { reconnectLock: lock })
    Object.assign(second.deps, { reconnectLock: lock })

    const pending = connect({ origin }, first.deps)
    await vi.waitFor(() => expect(first.deps.browserOpen).toHaveBeenCalledOnce())
    const competing = await connect({ origin }, second.deps).catch((caught: unknown) => caught)
    expect(competing).toMatchObject({ message: 'Reconnect already in progress.' })
    expect(second.requests).toHaveLength(0)
    releaseCallback()
    await expect(pending).resolves.toMatchObject({ origin })
  })

  it('keeps staged credentials usable when primary promotion fails', async () => {
    const previous = storedCredential()
    const accounts = new Map<string, StoredCredentials>([[origin, previous]])
    const flow = fakeFlow()
    const normalFetch = flow.deps.fetch
    flow.deps.fetch = vi.fn(async (input, init) => String(input).endsWith('/oauth/revoke')
      ? new Response(null, { status: 200 })
      : normalFetch(input, init))
    flow.deps.credentials = {
      assertAvailable: async () => undefined,
      get: async (account) => accounts.get(account) ?? null,
      set: async (account, value) => {
        if (account === origin && value.refreshToken === 'REFRESH-SECRET') throw new Error('promotion failed')
        accounts.set(account, value)
      },
      delete: async (account) => accounts.delete(account),
    }

    await expect(connect({ origin }, flow.deps)).rejects.toThrow(/recovery.*staged credentials remain usable/i)
    expect(accounts.get(origin)).toEqual(previous)
    expect(accounts.get(stagingAccount)).toMatchObject({ refreshToken: 'REFRESH-SECRET' })
  })

  it('keeps promoted credentials when staging cleanup fails', async () => {
    const previous = storedCredential()
    const accounts = new Map<string, StoredCredentials>([[origin, previous]])
    const flow = fakeFlow()
    flow.deps.credentials = {
      assertAvailable: async () => undefined,
      get: async (account) => accounts.get(account) ?? null,
      set: async (account, value) => { accounts.set(account, value) },
      delete: async (account) => {
        if (account === stagingAccount) throw new Error('cleanup failed')
        return accounts.delete(account)
      },
    }

    await expect(connect({ origin }, flow.deps)).resolves.toEqual({ origin, scopes: DEFAULT_READ_SCOPES })
    expect(accounts.get(origin)).toMatchObject({ refreshToken: 'REFRESH-SECRET' })
    expect(accounts.get(stagingAccount)).toMatchObject({ refreshToken: 'REFRESH-SECRET' })
  })

  it('does not start another OAuth flow until duplicate staging cleanup succeeds', async () => {
    const previous = storedCredential()
    const accounts = new Map<string, StoredCredentials>([[origin, previous]])
    const flow = fakeFlow()
    flow.deps.credentials = {
      assertAvailable: async () => undefined,
      get: async (account) => accounts.get(account) ?? null,
      set: async (account, value) => { accounts.set(account, value) },
      delete: async (account) => {
        if (account === stagingAccount) throw new Error('cleanup failed')
        return accounts.delete(account)
      },
    }

    await connect({ origin }, flow.deps)
    const requestCount = flow.requests.length
    await expect(connect({ origin }, flow.deps)).rejects.toThrow(/recovery.*cleanup/i)
    expect(flow.requests).toHaveLength(requestCount)
    expect(accounts.get(origin)).toMatchObject({ refreshToken: 'REFRESH-SECRET' })
    expect(accounts.get(stagingAccount)).toEqual(accounts.get(origin))
  })

  it('does not start OAuth when promoted fallback cleanup fails', async () => {
    const previous = storedCredential()
    const fallback = storedCredential({
      accessToken: 'fallback-access', clientId: 'fallback-client', refreshToken: 'fallback-refresh',
    })
    const accounts = new Map<string, StoredCredentials>([
      [origin, previous],
      [fallbackStagingAccount, fallback],
    ])
    const flow = fakeFlow()
    const normalFetch = flow.deps.fetch
    let revocations = 0
    flow.deps.fetch = vi.fn(async (input, init) => {
      if (String(input).endsWith('/oauth/revoke')) {
        revocations += 1
        return new Response(null, { status: 200 })
      }
      return normalFetch(input, init)
    })
    flow.deps.credentials = {
      assertAvailable: async () => undefined,
      get: async (account) => accounts.get(account) ?? null,
      set: async (account, value) => { accounts.set(account, value) },
      delete: async (account) => {
        if (account === fallbackStagingAccount) throw new Error('cleanup failed')
        return accounts.delete(account)
      },
    }

    await expect(connect({ origin }, flow.deps)).rejects.toThrow(/recovery.*cleanup/i)
    expect(revocations).toBe(1)
    expect(flow.requests).toHaveLength(0)
    expect(accounts.get(origin)).toMatchObject({ ...fallback, tokenVersion: 0 })
    expect(accounts.get(origin)?.grantId).toMatch(/^[A-Za-z0-9_-]+$/)
    expect(accounts.get(fallbackStagingAccount)).toEqual(accounts.get(origin))
  })

  it('never revokes a tampered prior credential against another origin', async () => {
    const previous: StoredCredentials = {
      accessToken: 'old-access', clientId: 'old-client', expiresAt: 1,
      origin: 'https://evil.example.test',
      redirectUri: 'http://127.0.0.1:45678/oauth/callback', refreshToken: 'old-refresh',
      scopes: ['clients:read'], tokenEndpoint: 'https://evil.example.test/oauth/token',
    }
    const flow = fakeFlow()
    flow.deps.credentials.get = vi.fn(async (account) => account === origin ? previous : null)

    await expect(connect({ origin }, flow.deps)).rejects.toThrow(/stored credentials.*origin/i)
    expect(flow.requests.some((request) => request.url.startsWith('https://evil.example.test'))).toBe(false)
    expect(flow.deps.credentials.set).not.toHaveBeenCalled()
  })

  it('deletes only configured-origin credentials on logout', async () => {
    const flow = fakeFlow()
    const current: StoredCredentials = {
      accessToken: 'access', clientId: 'client', expiresAt: 1, origin,
      issuer,
      redirectUri: 'http://127.0.0.1:45678/oauth/callback', refreshToken: 'refresh',
      scopes: ['clients:read'], tokenEndpoint: `${issuer}/oauth/token`,
    }
    flow.deps.credentials.get = vi.fn(async (account) => account === origin ? current : null)
    await logout(origin, flow.deps)
    const revocation = flow.requests.find((request) => request.url.endsWith('/oauth/revoke'))!
    expect(revocation.url).toBe(`${issuer}/oauth/revoke`)
    expect(await revocation.text()).toBe('client_id=client&token=refresh&token_type_hint=refresh_token')
    expect(revocation.redirect).toBe('manual')
    expect(flow.deps.credentials.delete).toHaveBeenCalledWith(origin)
  })

  it('does not delete local credentials when remote revocation fails', async () => {
    const current: StoredCredentials = {
      accessToken: 'access', clientId: 'client', expiresAt: 1, origin,
      redirectUri: 'http://127.0.0.1:45678/oauth/callback', refreshToken: 'refresh',
      scopes: ['clients:read'], tokenEndpoint: `${origin}/oauth/token`,
    }
    const remove = vi.fn(async () => true)
    const dependencies = {
      fetch: vi.fn(async () => new Response(null, { status: 500 })),
      credentials: {
        assertAvailable: async () => undefined, get: async (account) => account === origin ? current : null,
        set: async () => undefined, delete: remove,
      },
      now: Date.now,
    }

    await expect(logout(origin, dependencies)).rejects.toThrow(/revocation.*500/i)
    expect(remove).not.toHaveBeenCalled()
  })

  it('revokes primary and staged grants before deleting either on logout', async () => {
    const primary = storedCredential()
    const staged = storedCredential({
      accessToken: 'new-access', clientId: 'new-client', refreshToken: 'new-refresh',
    })
    const accounts = new Map<string, StoredCredentials>([
      [origin, primary],
      [stagingAccount, staged],
    ])
    const revoked: string[] = []
    const deleted: string[] = []
    const dependencies = {
      fetch: vi.fn(async (_input: URL | RequestInfo, init?: RequestInit) => {
        revoked.push(new URLSearchParams(String(init?.body)).get('token')!)
        return new Response(null, { status: 200 })
      }),
      credentials: {
        assertAvailable: async () => undefined,
        get: async (account: string) => accounts.get(account) ?? null,
        set: async () => undefined,
        delete: async (account: string) => {
          deleted.push(account)
          return accounts.delete(account)
        },
      },
      now: Date.now,
    }

    await logout(origin, dependencies)

    expect(revoked).toEqual(['old-refresh', 'new-refresh'])
    expect(deleted).toEqual([stagingAccount, origin])
    expect(accounts.size).toBe(0)
  })

  it('revokes one current token for diverged snapshots of the same grant on logout', async () => {
    const primary = storedCredential({
      accessToken: 'new-access', refreshToken: 'new-refresh', expiresAt: 1_900_000_600_000,
      tokenVersion: 1,
    })
    const staleDuplicate = storedCredential({
      accessToken: 'old-access', refreshToken: 'old-refresh', expiresAt: 1_900_000_000_000,
      tokenVersion: 0,
    })
    const accounts = new Map<string, StoredCredentials>([
      [origin, primary],
      [stagingAccount, staleDuplicate],
    ])
    const revoked: string[] = []

    await logout(origin, {
      fetch: vi.fn(async (_input, init) => {
        revoked.push(new URLSearchParams(String(init?.body)).get('token')!)
        return new Response(null, { status: 200 })
      }),
      credentials: {
        assertAvailable: async () => undefined,
        get: async (account) => accounts.get(account) ?? null,
        set: async () => undefined,
        delete: async (account) => accounts.delete(account),
      },
      now: Date.now,
    })

    expect(revoked).toEqual(['new-refresh'])
    expect(accounts.size).toBe(0)
  })

  it('keeps separate same-client authorizations distinct by explicit grant identity', async () => {
    const first = storedCredential({
      grantId: Buffer.alloc(32, 1).toString('base64url'),
      refreshToken: 'first-refresh',
    })
    const second = storedCredential({
      grantId: Buffer.alloc(32, 2).toString('base64url'),
      refreshToken: 'second-refresh',
    })
    const accounts = new Map<string, StoredCredentials>([
      [origin, first],
      [stagingAccount, second],
    ])
    const revoked: string[] = []

    await logout(origin, {
      fetch: vi.fn(async (_input, init) => {
        revoked.push(new URLSearchParams(String(init?.body)).get('token')!)
        return new Response(null, { status: 200 })
      }),
      credentials: {
        assertAvailable: async () => undefined,
        get: async (account) => accounts.get(account) ?? null,
        set: async () => undefined,
        delete: async (account) => accounts.delete(account),
      },
      now: Date.now,
    })

    expect(revoked).toEqual(['first-refresh', 'second-refresh'])
    expect(accounts.size).toBe(0)
  })

  it('does not let logout mutate credentials during a locked reconnect', async () => {
    const lockedOrigin = `https://logout-lock-${process.pid}.example.test`
    const release = await nativeReconnectLock.acquire(lockedOrigin)
    const current = storedCredential({
      origin: lockedOrigin,
      tokenEndpoint: `${lockedOrigin}/oauth/token`,
    })
    const fetch = vi.fn(async () => new Response(null, { status: 200 }))
    const remove = vi.fn(async () => true)
    try {
      await expect(logout(lockedOrigin, {
        fetch,
        credentials: {
          assertAvailable: async () => undefined,
          get: async (account) => account === lockedOrigin ? current : null,
          set: async () => undefined,
          delete: remove,
        },
        now: Date.now,
        reconnectLock: nativeReconnectLock,
      })).rejects.toThrow(/already in progress/i)
    } finally {
      await release()
    }
    expect(fetch).not.toHaveBeenCalled()
    expect(remove).not.toHaveBeenCalled()
  })

  it('fails closed before OAuth when the native keyring is unavailable', async () => {
    const flow = fakeFlow({
      credentials: {
        assertAvailable: vi.fn(async () => { throw new Error('locked') }),
        get: vi.fn(), set: vi.fn(), delete: vi.fn(),
      },
    })

    await expect(connect({ origin }, flow.deps)).rejects.toThrow(/native MCP OAuth.*secret manager/i)
    expect(flow.requests).toHaveLength(0)
    expect(flow.deps.browserOpen).not.toHaveBeenCalled()
  })

  it('requires an explicit safe origin and rejects paths or insecure remote HTTP', () => {
    expect(resolveOrigin(`${origin}/`, undefined)).toBe(origin)
    expect(resolveOrigin(undefined, origin)).toBe(origin)
    expect(() => resolveOrigin(undefined, undefined)).toThrow(/--origin.*ATHLENDRA_ORIGIN/)
    expect(() => resolveOrigin(`${origin}/auth`, undefined)).toThrow(/origin/)
    expect(() => resolveOrigin('http://athlendra.example.test', undefined)).toThrow(/HTTPS/)
    expect(resolveOrigin('http://127.0.0.1:8787', undefined)).toBe('http://127.0.0.1:8787')
  })
})

describe('loopback callback server', () => {
  it('ignores racing invalid callbacks and accepts only exact state, issuer, path, and method', async () => {
    const session = await startLoopbackCallbackServer({
      expectedState: 'state', expectedIssuer: origin, timeoutMs: 1_000,
    })
    const redirect = new URL(session.redirectUri)
    expect(redirect.hostname).toBe('127.0.0.1')
    expect(Number(redirect.port)).toBeGreaterThan(0)
    expect(redirect.pathname).toBe('/oauth/callback')

    const callback = session.waitForCallback()
    const wrong = await fetch(new URL('/wrong', redirect))
    expect(wrong.status).toBe(404)
    const wrongMethod = await fetch(session.redirectUri, { method: 'POST' })
    expect(wrongMethod.status).toBe(404)
    const badState = await fetch(`${session.redirectUri}?code=stolen&state=wrong&iss=${encodeURIComponent(origin)}`)
    expect(badState.status).toBe(400)
    expect(await badState.text()).not.toContain('connected')
    const badIssuer = await fetch(`${session.redirectUri}?code=stolen&state=state&iss=${encodeURIComponent('https://evil.test')}`)
    expect(badIssuer.status).toBe(400)
    expect(await badIssuer.text()).not.toContain('connected')
    const accepted = await fetch(`${session.redirectUri}?code=abc&state=state&iss=${encodeURIComponent(origin)}`)
    expect(accepted.status).toBe(200)
    expect(await accepted.text()).toContain('connected')
    await expect(callback).resolves.toEqual({ code: 'abc', state: 'state', issuer: origin })
    const duplicate = await fetch(`${session.redirectUri}?code=second&state=state&iss=${encodeURIComponent(origin)}`)
    expect(duplicate.status).toBe(409)
    expect(await duplicate.text()).not.toContain('connected')
    await session.close()
  })

  it('times out and cancels callback waits safely', async () => {
    const timed = await startLoopbackCallbackServer({
      expectedState: 'state', expectedIssuer: origin, timeoutMs: 10,
    })
    await expect(timed.waitForCallback()).rejects.toThrow(/timed out/i)
    await timed.close()

    const cancelled = await startLoopbackCallbackServer({
      expectedState: 'state', expectedIssuer: origin, timeoutMs: 1_000,
    })
    const waiting = cancelled.waitForCallback()
    await cancelled.close()
    await expect(waiting).rejects.toThrow(/cancelled/i)
  })
})
