import { createHash, randomBytes as nodeRandomBytes } from 'node:crypto'
import type { CallbackServer } from './callback-server.js'
import type { CredentialStore } from './credentials.js'
import { keyringUnavailable } from './credentials.js'
import { CliError, objectValue, postWithoutRedirect, readJsonResponse, requireString } from './http.js'
import { nativeReconnectLock, type ReconnectLock } from './reconnect-lock.js'

export const DEFAULT_READ_SCOPES = [
  'clients:read',
  'programs:read',
  'sessions:read',
  'progress:read',
  'exercises:read',
  'notes:read',
] as const

export const FULL_SCOPES = [
  'clients:read',
  'clients:write',
  'programs:read',
  'programs:write',
  'sessions:read',
  'sessions:write',
  'progress:read',
  'exercises:read',
  'exercises:write',
  'notes:read',
  'notes:write',
] as const

const releasedScopes = new Set<string>(FULL_SCOPES)

export interface StoredCredentials {
  origin: string
  issuer?: string
  clientId: string
  grantId?: string
  redirectUri: string
  tokenEndpoint: string
  accessToken: string
  refreshToken: string
  expiresAt: number
  scopes: string[]
  tokenVersion?: number
}

export interface NormalizedStoredCredentials extends StoredCredentials {
  issuer: string
}

export interface TokenDependencies {
  fetch: typeof globalThis.fetch
  credentials: CredentialStore
  now(): number
  reconnectLock?: ReconnectLock
}

export interface LoadedCredentials {
  account: string
  accounts: string[]
  credentials: NormalizedStoredCredentials
}

export function reconnectStagingAccount(origin: string): string {
  return `reconnect:v1:${originOnly(origin)}`
}

function fallbackReconnectStagingAccount(origin: string): string {
  return `reconnect:v1:fallback:${originOnly(origin)}`
}

function reconnectStagingAccounts(origin: string): string[] {
  return [reconnectStagingAccount(origin), fallbackReconnectStagingAccount(origin)]
}

export interface AuthDependencies extends TokenDependencies {
  browserOpen(url: string): Promise<unknown>
  callbackServer: CallbackServer
  randomBytes(size: number): Uint8Array
}

export interface ConnectOptions {
  origin: string
  profile?: 'read' | 'full'
  scopes?: string[]
}

function originOnly(value: string): string {
  let url: URL
  try {
    url = new URL(value)
  } catch {
    throw new CliError('Athlendra origin must be a valid URL origin.')
  }
  if (url.username || url.password || url.search || url.hash || (url.pathname !== '/' && url.pathname !== '')) {
    throw new CliError('Athlendra origin must contain only scheme, host, and optional port.')
  }
  const loopback = url.hostname === '127.0.0.1' || url.hostname === 'localhost' || url.hostname === '[::1]'
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) {
    throw new CliError('Athlendra origin must use HTTPS, except local loopback development origins.')
  }
  return url.origin
}

export function resolveOrigin(option: string | undefined, environment: string | undefined): string {
  const value = option ?? environment
  if (!value) {
    throw new CliError('Set --origin or ATHLENDRA_ORIGIN. This build has no claimed production-domain default.')
  }
  return originOnly(value)
}

function validateRequestedScopeNames(options: ConnectOptions): void {
  for (const scope of options.scopes ?? []) {
    if (!releasedScopes.has(scope)) throw new CliError(`Unsupported scope: ${scope}`)
  }
}

function supportedScopes(value: unknown): string[] {
  if (!Array.isArray(value) || value.length === 0
    || value.some((scope) => typeof scope !== 'string' || !releasedScopes.has(scope))) {
    throw new CliError('OAuth resource discovery returned invalid scopes_supported.')
  }
  return [...new Set(value as string[])]
}

function selectedScopes(options: ConnectOptions, advertised: readonly string[]): string[] {
  const requested = options.scopes?.length
    ? [...new Set(options.scopes)]
    : options.profile === 'full' ? [...advertised] : [...DEFAULT_READ_SCOPES]
  const available = new Set(advertised)
  for (const scope of requested) {
    if (!releasedScopes.has(scope) || !available.has(scope)) {
      throw new CliError(`Unsupported scope: ${scope}`)
    }
  }
  if (requested.length === 0) throw new CliError('At least one scope is required.')
  return requested
}

function authorizationServer(value: unknown): string {
  if (!Array.isArray(value) || value.length !== 1 || typeof value[0] !== 'string') {
    throw new CliError('OAuth resource metadata must list exactly one HTTPS authorization server.')
  }
  let parsed: URL
  try {
    parsed = new URL(value[0])
  } catch {
    throw new CliError('OAuth resource metadata listed an invalid authorization server.')
  }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.search || parsed.hash
    || (parsed.pathname !== '/' && parsed.pathname !== '')) {
    throw new CliError('OAuth resource metadata authorization server must be an HTTPS origin.')
  }
  return parsed.origin
}

function endpoint(value: unknown, key: string, issuer: string): string {
  if (typeof value !== 'string') throw new CliError(`OAuth metadata omitted ${key}.`)
  let parsed: URL
  try {
    parsed = new URL(value)
  } catch {
    throw new CliError(`OAuth ${key} must be a valid URL.`)
  }
  if (parsed.origin !== issuer) throw new CliError(`OAuth ${key} must use the configured issuer.`)
  return parsed.toString()
}

async function responseObject(
  response: Response,
  context: string,
  allowedStatuses: readonly number[] = [200],
): Promise<Record<string, unknown>> {
  const value = objectValue(await readJsonResponse(response, context), context)
  if (!allowedStatuses.includes(response.status)) {
    const code = typeof value.error === 'string' ? value.error : `HTTP ${response.status}`
    throw new CliError(`${context} failed: ${code}.`)
  }
  return value
}

function parseToken(
  value: Record<string, unknown>,
  expectedResource: string,
  now: number,
  previousRefreshToken?: string,
): Pick<StoredCredentials, 'accessToken' | 'refreshToken' | 'expiresAt' | 'scopes'> {
  const accessToken = requireString(value, 'access_token', 'OAuth token endpoint')
  const refreshToken = typeof value.refresh_token === 'string' && value.refresh_token.length > 0
    ? value.refresh_token
    : previousRefreshToken
  if (!refreshToken) throw new CliError('OAuth token endpoint omitted refresh_token.')
  if (typeof value.token_type !== 'string' || value.token_type.toLowerCase() !== 'bearer') {
    throw new CliError('OAuth token endpoint returned an unsupported token type.')
  }
  if (value.resource !== expectedResource) throw new CliError('OAuth token resource does not match the configured REST API.')
  if (typeof value.expires_in !== 'number' || !Number.isFinite(value.expires_in) || value.expires_in <= 0) {
    throw new CliError('OAuth token endpoint returned invalid expiry data.')
  }
  const scopes = typeof value.scope === 'string' ? value.scope.split(/\s+/).filter(Boolean) : []
  return { accessToken, refreshToken, expiresAt: now + value.expires_in * 1000, scopes }
}

async function assertKeyring(store: CredentialStore): Promise<void> {
  try {
    await store.assertAvailable()
  } catch {
    throw keyringUnavailable()
  }
}

function assertStoredOrigin(credentials: StoredCredentials | null, origin: string): void {
  if (credentials && credentials.origin !== origin) {
    throw new CliError('Stored credentials do not match configured origin.')
  }
}

function legacyGrantId(origin: string, clientId: string): string {
  return createHash('sha256')
    .update(`coachforge-cli-legacy-grant-v1\0${origin}\0${clientId}`)
    .digest('base64url')
}

function newGrantId(origin: string, clientId: string, state: string): string {
  return createHash('sha256')
    .update(`coachforge-cli-grant-v1\0${origin}\0${clientId}\0${state}`)
    .digest('base64url')
}

function normalizeStoredCredentials(credentials: StoredCredentials): NormalizedStoredCredentials {
  const grantId = credentials.grantId ?? legacyGrantId(credentials.origin, credentials.clientId)
  if (!/^[A-Za-z0-9_-]{43}$/.test(grantId)) {
    throw new CliError('Stored credential grant identity is invalid.')
  }
  if (credentials.tokenVersion !== undefined
    && (!Number.isInteger(credentials.tokenVersion) || credentials.tokenVersion < 0)) {
    throw new CliError('Stored credential token version is invalid.')
  }
  return {
    ...credentials,
    issuer: originOnly(credentials.issuer ?? credentials.origin),
    grantId,
    tokenVersion: credentials.tokenVersion ?? 0,
  }
}

function sameGrant(left: NormalizedStoredCredentials, right: NormalizedStoredCredentials): boolean {
  return left.origin === right.origin && left.grantId === right.grantId
}

function sameSnapshot(left: NormalizedStoredCredentials, right: NormalizedStoredCredentials): boolean {
  return left.origin === right.origin
    && left.issuer === right.issuer
    && left.clientId === right.clientId
    && left.grantId === right.grantId
    && left.redirectUri === right.redirectUri
    && left.tokenEndpoint === right.tokenEndpoint
    && left.accessToken === right.accessToken
    && left.refreshToken === right.refreshToken
    && left.expiresAt === right.expiresAt
    && left.scopes.length === right.scopes.length
    && left.scopes.every((scope, index) => scope === right.scopes[index])
    && left.tokenVersion === right.tokenVersion
}

function latestCredential(entries: LoadedCredentials[]): LoadedCredentials {
  return entries.reduce((latest, candidate) => {
    const latestVersion = latest.credentials.tokenVersion ?? 0
    const candidateVersion = candidate.credentials.tokenVersion ?? 0
    if (candidateVersion !== latestVersion) return candidateVersion > latestVersion ? candidate : latest
    return candidate.credentials.expiresAt > latest.credentials.expiresAt ? candidate : latest
  })
}

async function cleanupStagingCredential(store: CredentialStore, account: string): Promise<boolean> {
  try {
    await store.delete(account)
    return true
  } catch {
    // Primary credentials are already durable. A later load retries cleanup.
    return false
  }
}

async function consolidateStagedEntries(
  entries: LoadedCredentials[],
  authoritative: NormalizedStoredCredentials,
  dependencies: TokenDependencies,
  strict: boolean,
): Promise<string[]> {
  const survivingAccounts: string[] = []
  for (const entry of entries) {
    const cleaned = await cleanupStagingCredential(dependencies.credentials, entry.account)
    if (cleaned) continue
    try {
      await dependencies.credentials.set(entry.account, authoritative)
    } catch {
      // Stable grant identity lets later recovery delete or update this stale snapshot without revocation.
    }
    survivingAccounts.push(entry.account)
    if (strict) throw new CliError('Reconnect recovery cleanup failed; stored credentials remain usable.')
  }
  return survivingAccounts
}

async function recoverCredentials(
  origin: string,
  dependencies: TokenDependencies,
  strict: boolean,
): Promise<LoadedCredentials | null> {
  const primaryValue = await dependencies.credentials.get(origin)
  const stagedEntries = (await Promise.all(reconnectStagingAccounts(origin).map(async (account) => ({
    account,
    credentials: await dependencies.credentials.get(account),
    accounts: [account],
  })))).filter((entry): entry is LoadedCredentials => entry.credentials !== null)
  assertStoredOrigin(primaryValue, origin)
  for (const entry of stagedEntries) assertStoredOrigin(entry.credentials, origin)
  const primary = primaryValue ? normalizeStoredCredentials(primaryValue) : null
  for (const entry of stagedEntries) entry.credentials = normalizeStoredCredentials(entry.credentials)
  if (stagedEntries.length === 0) {
    return primary ? { account: origin, accounts: [origin], credentials: primary } : null
  }
  const staged = latestCredential(stagedEntries)
  if (stagedEntries.some((entry) => !sameGrant(entry.credentials, staged.credentials))) {
    throw new CliError('Multiple reconnect recovery grants are stored. Run logout before connecting again.')
  }

  if (primary && sameGrant(primary, staged.credentials)) {
    const authoritative = latestCredential([
      { account: origin, accounts: [origin], credentials: primary },
      ...stagedEntries,
    ])
    if (!sameSnapshot(primary, authoritative.credentials)) {
      try {
        await dependencies.credentials.set(origin, authoritative.credentials)
      } catch {
        return {
          account: authoritative.account,
          accounts: [authoritative.account, origin, ...stagedEntries
            .map((entry) => entry.account)
            .filter((account) => account !== authoritative.account)],
          credentials: authoritative.credentials,
        }
      }
    }
    const survivingAccounts = await consolidateStagedEntries(
      stagedEntries,
      authoritative.credentials,
      dependencies,
      strict,
    )
    return {
      account: origin,
      accounts: [origin, ...survivingAccounts],
      credentials: authoritative.credentials,
    }
  }

  if (primary) {
    try {
      await revokeCredentials(primary, dependencies)
    } catch (caught) {
      if (strict) {
        const message = caught instanceof Error ? caught.message : 'prior grant revocation failed.'
        throw new CliError(`Reconnect recovery stopped: ${message} New credentials remain stored in the recovery account.`)
      }
      return {
        ...staged,
        accounts: stagedEntries.map((entry) => entry.account),
      }
    }
  }

  try {
    await dependencies.credentials.set(origin, staged.credentials)
  } catch {
    if (strict) {
      throw new CliError('Reconnect recovery could not promote credentials; staged credentials remain usable.')
    }
    return {
      ...staged,
      accounts: stagedEntries.map((entry) => entry.account),
    }
  }
  const survivingAccounts = await consolidateStagedEntries(
    stagedEntries,
    staged.credentials,
    dependencies,
    strict,
  )
  return {
    account: origin,
    accounts: [origin, ...survivingAccounts],
    credentials: staged.credentials,
  }
}

export async function loadCredentialsWithLockHeld(
  originValue: string,
  dependencies: TokenDependencies,
): Promise<LoadedCredentials | null> {
  const origin = originOnly(originValue)
  await assertKeyring(dependencies.credentials)
  return recoverCredentials(origin, dependencies, false)
}

export async function acquireReconnectLock(
  originValue: string,
  dependencies: TokenDependencies,
): Promise<() => Promise<void>> {
  const origin = originOnly(originValue)
  return (dependencies.reconnectLock ?? nativeReconnectLock).acquire(origin)
}

export async function loadCredentials(
  originValue: string,
  dependencies: TokenDependencies,
): Promise<LoadedCredentials | null> {
  const release = await acquireReconnectLock(originValue, dependencies)
  try {
    return await loadCredentialsWithLockHeld(originValue, dependencies)
  } finally {
    await release()
  }
}

async function connectLocked(
  options: ConnectOptions,
  dependencies: AuthDependencies,
): Promise<{ origin: string; scopes: string[] }> {
  const origin = originOnly(options.origin)
  validateRequestedScopeNames(options)
  await assertKeyring(dependencies.credentials)
  const recovered = await recoverCredentials(origin, dependencies, true)
  const previous = recovered?.credentials ?? null
  const resource = `${origin}/api/agent/v1`
  const protectedMetadataResponse = await dependencies.fetch(
    `${origin}/.well-known/oauth-protected-resource/api/agent/v1`,
  )
  const protectedMetadata = await responseObject(protectedMetadataResponse, 'OAuth resource discovery')
  if (protectedMetadata.resource !== resource) throw new CliError('OAuth resource metadata does not match the configured REST API.')
  const issuer = authorizationServer(protectedMetadata.authorization_servers)
  const scopes = selectedScopes(options, supportedScopes(protectedMetadata.scopes_supported))

  const authorizationMetadataResponse = await dependencies.fetch(
    `${issuer}/.well-known/oauth-authorization-server`,
  )
  const authorizationMetadata = await responseObject(authorizationMetadataResponse, 'OAuth issuer discovery')
  if (authorizationMetadata.issuer !== issuer) throw new CliError('OAuth issuer metadata does not match the configured issuer.')
  if (!Array.isArray(authorizationMetadata.code_challenge_methods_supported)
    || !authorizationMetadata.code_challenge_methods_supported.includes('S256')) {
    throw new CliError('OAuth issuer does not support S256 PKCE.')
  }
  const authorizationEndpoint = endpoint(authorizationMetadata.authorization_endpoint, 'authorization_endpoint', issuer)
  const tokenEndpoint = endpoint(authorizationMetadata.token_endpoint, 'token_endpoint', issuer)
  const registrationEndpoint = endpoint(authorizationMetadata.registration_endpoint, 'registration_endpoint', issuer)
  const state = Buffer.from(dependencies.randomBytes(32)).toString('base64url')
  const verifier = Buffer.from(dependencies.randomBytes(64)).toString('base64url')
  const challenge = createHash('sha256').update(verifier).digest('base64url')
  const callback = await dependencies.callbackServer.start({
    expectedState: state,
    expectedIssuer: issuer,
  })

  try {
    const registrationResponse = await postWithoutRedirect(dependencies.fetch, registrationEndpoint, {
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        client_name: 'Athlendra CLI',
        grant_types: ['authorization_code', 'refresh_token'],
        redirect_uris: [callback.redirectUri],
        response_types: ['code'],
        token_endpoint_auth_method: 'none',
      }),
    }, 'OAuth client registration')
    const registration = await responseObject(registrationResponse, 'OAuth client registration', [200, 201])
    const clientId = requireString(registration, 'client_id', 'OAuth client registration')
    const authorizationUrl = new URL(authorizationEndpoint)
    for (const [key, value] of Object.entries({
      client_id: clientId,
      code_challenge: challenge,
      code_challenge_method: 'S256',
      redirect_uri: callback.redirectUri,
      resource,
      response_type: 'code',
      scope: scopes.join(' '),
      state,
    })) authorizationUrl.searchParams.set(key, value)

    await dependencies.browserOpen(authorizationUrl.toString())
    const authorization = await callback.waitForCallback()
    if (authorization.state !== state) throw new CliError('OAuth callback state mismatch.')
    if (authorization.issuer !== issuer) throw new CliError('OAuth callback issuer mismatch.')

    const tokenResponse = await postWithoutRedirect(dependencies.fetch, tokenEndpoint, {
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: clientId,
        code: authorization.code,
        code_verifier: verifier,
        grant_type: 'authorization_code',
        redirect_uri: callback.redirectUri,
        resource,
      }),
    }, 'OAuth code exchange')
    const token = parseToken(
      await responseObject(tokenResponse, 'OAuth code exchange'),
      resource,
      dependencies.now(),
    )
    const credentials: StoredCredentials = {
      ...token,
      scopes: token.scopes.length > 0 ? token.scopes : scopes,
      origin,
      issuer,
      clientId,
      grantId: newGrantId(origin, clientId, state),
      redirectUri: callback.redirectUri,
      tokenEndpoint,
      tokenVersion: 0,
    }
    const stagingAccount = reconnectStagingAccount(origin)
    try {
      await dependencies.credentials.set(stagingAccount, credentials)
    } catch {
      try {
        await revokeCredentials(credentials, dependencies)
      } catch {
        try {
          await dependencies.credentials.set(fallbackReconnectStagingAccount(origin), credentials)
        } catch {
          throw new CliError(
            `New OAuth grant for client ${clientId} could not be stored or revoked. `
            + 'Existing credentials remain unchanged. Revoke this client or grant in the configured service before reconnecting.',
          )
        }
        throw new CliError('Compensating grant revocation failed; new credentials remain stored in the fallback recovery account.')
      }
      throw new CliError('New credentials could not be staged; the new grant was revoked and prior credentials remain unchanged.')
    }
    if (previous) {
      try {
        await revokeCredentials(previous, dependencies)
      } catch (caught) {
        const message = caught instanceof Error ? caught.message : 'prior grant revocation failed.'
        throw new CliError(`Reconnect recovery stopped: ${message} New credentials remain stored in the recovery account.`)
      }
    }
    try {
      await dependencies.credentials.set(origin, credentials)
    } catch {
      throw new CliError('Reconnect recovery could not promote credentials; staged credentials remain usable.')
    }
    await cleanupStagingCredential(dependencies.credentials, stagingAccount)
    return { origin, scopes: credentials.scopes }
  } finally {
    await callback.close()
  }
}

export async function connect(
  options: ConnectOptions,
  dependencies: AuthDependencies,
): Promise<{ origin: string; scopes: string[] }> {
  const origin = originOnly(options.origin)
  const release = await acquireReconnectLock(origin, dependencies)
  try {
    return await connectLocked({ ...options, origin }, dependencies)
  } finally {
    await release()
  }
}

export async function refreshCredentials(
  loaded: LoadedCredentials,
  dependencies: TokenDependencies,
): Promise<LoadedCredentials> {
  await assertKeyring(dependencies.credentials)
  const normalized = normalizeStoredCredentials(loaded.credentials)
  let tokenEndpoint: URL
  try {
    tokenEndpoint = new URL(normalized.tokenEndpoint)
  } catch {
    throw new CliError('Stored OAuth token endpoint is invalid.')
  }
  if (tokenEndpoint.origin !== originOnly(normalized.issuer)) {
    throw new CliError('Stored OAuth token endpoint does not match the credential issuer.')
  }
  const origin = originOnly(normalized.origin)
  const accounts = [...new Set(loaded.accounts)]
  for (const account of accounts) {
    if (account !== origin && !reconnectStagingAccounts(origin).includes(account)) {
      throw new CliError('Credential storage account does not match the credential origin.')
    }
  }
  const sameGrantAccounts: string[] = []
  for (const account of accounts) {
    const stored = await dependencies.credentials.get(account)
    if (!stored) continue
    assertStoredOrigin(stored, origin)
    if (sameGrant(normalizeStoredCredentials(stored), normalized)) sameGrantAccounts.push(account)
  }
  if (sameGrantAccounts.length === 0) {
    throw new CliError('No stored credential account matches the OAuth grant; refusing refresh.')
  }
  const resource = `${normalized.origin}/api/agent/v1`
  const response = await postWithoutRedirect(dependencies.fetch, tokenEndpoint, {
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: normalized.clientId,
      grant_type: 'refresh_token',
      refresh_token: normalized.refreshToken,
      resource,
    }),
  }, 'OAuth token refresh')
  const token = parseToken(
    await responseObject(response, 'OAuth token refresh'),
    resource,
    dependencies.now(),
    normalized.refreshToken,
  )
  const rotated = {
    ...normalized,
    ...token,
    scopes: token.scopes.length > 0 ? token.scopes : normalized.scopes,
    tokenVersion: (normalized.tokenVersion ?? 0) + 1,
  }
  const storedAccounts: string[] = []
  for (const account of sameGrantAccounts) {
    try {
      await dependencies.credentials.set(account, rotated)
      storedAccounts.push(account)
    } catch {
      // Try every same-grant replica. One durable keyring copy preserves access after rotation.
    }
  }
  if (storedAccounts.length === 0) {
    throw new CliError(
      `OAuth refresh rotated the grant, but no updated credential could be stored in the OS keyring. `
      + `Revoke client ${normalized.clientId} in the configured service, restore keyring access, then reconnect.`,
    )
  }
  return {
    account: storedAccounts.includes(loaded.account) ? loaded.account : storedAccounts[0],
    accounts: sameGrantAccounts,
    credentials: rotated,
  }
}

export async function revokeCredentials(
  current: StoredCredentials,
  dependencies: TokenDependencies,
): Promise<void> {
  const issuer = originOnly(current.issuer ?? current.origin)
  const response = await postWithoutRedirect(dependencies.fetch, `${issuer}/oauth/revoke`, {
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: current.clientId,
      token: current.refreshToken,
      token_type_hint: 'refresh_token',
    }),
  }, 'OAuth grant revocation')
  if (response.status !== 200) {
    throw new CliError(`OAuth grant revocation failed with HTTP ${response.status}.`)
  }
}

async function logoutWithLockHeld(originValue: string, dependencies: TokenDependencies): Promise<void> {
  const origin = originOnly(originValue)
  await assertKeyring(dependencies.credentials)
  const primaryValue = await dependencies.credentials.get(origin)
  const stagedEntries = (await Promise.all(reconnectStagingAccounts(origin).map(async (account) => ({
    account,
    credentials: await dependencies.credentials.get(account),
    accounts: [account],
  })))).filter((entry): entry is LoadedCredentials => entry.credentials !== null)
  assertStoredOrigin(primaryValue, origin)
  for (const entry of stagedEntries) assertStoredOrigin(entry.credentials, origin)
  const primary = primaryValue ? normalizeStoredCredentials(primaryValue) : null
  for (const entry of stagedEntries) entry.credentials = normalizeStoredCredentials(entry.credentials)
  if (!primary && stagedEntries.length === 0) return

  const entries = [
    ...(primary ? [{ account: origin, accounts: [origin], credentials: primary }] : []),
    ...stagedEntries,
  ]
  const grantIds = [...new Set(entries.map((entry) => entry.credentials.grantId!))]
  for (const grantId of grantIds) {
    const current = latestCredential(entries.filter((entry) => entry.credentials.grantId === grantId))
    await revokeCredentials(current.credentials, dependencies)
  }

  for (const account of [...stagedEntries.map((entry) => entry.account), primary ? origin : null]) {
    if (!account) continue
    let deleted: boolean
    try {
      deleted = await dependencies.credentials.delete(account)
    } catch {
      throw keyringUnavailable()
    }
    if (!deleted) throw new CliError('OS keyring credential could not be deleted.')
  }
}

export async function logout(originValue: string, dependencies: TokenDependencies): Promise<void> {
  const release = await acquireReconnectLock(originValue, dependencies)
  try {
    await logoutWithLockHeld(originValue, dependencies)
  } finally {
    await release()
  }
}

export const systemRandomBytes = (size: number): Uint8Array => nodeRandomBytes(size)
