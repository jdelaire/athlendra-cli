import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'

export interface OAuthCallback {
  code: string
  state: string
  issuer: string
}

export interface CallbackSession {
  redirectUri: string
  waitForCallback(): Promise<OAuthCallback>
  close(): Promise<void>
}

export interface CallbackExpectation {
  expectedState: string
  expectedIssuer: string
  timeoutMs?: number
}

export interface CallbackServer {
  start(expectation: CallbackExpectation): Promise<CallbackSession>
}

function closeServer(server: Server): Promise<void> {
  if (!server.listening) return Promise.resolve()
  return new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve())
  })
}

export async function startLoopbackCallbackServer(
  expectation: CallbackExpectation,
): Promise<CallbackSession> {
  let settled = false
  let settle: ((value: OAuthCallback) => void) | undefined
  let reject: ((error: Error) => void) | undefined
  const callback = new Promise<OAuthCallback>((resolve, rejectCallback) => {
    settle = resolve
    reject = rejectCallback
  })
  void callback.catch(() => undefined)
  const server = createServer((request, response) => {
    const requestUrl = new URL(request.url ?? '/', 'http://127.0.0.1')
    if (request.method !== 'GET' || requestUrl.pathname !== '/oauth/callback') {
      response.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' })
      response.end('Not found')
      return
    }
    if (settled) {
      response.writeHead(409, { 'content-type': 'text/plain; charset=utf-8' })
      response.end('Authorization callback already completed.')
      return
    }
    const state = requestUrl.searchParams.get('state')
    const issuer = requestUrl.searchParams.get('iss')
    if (state !== expectation.expectedState || issuer !== expectation.expectedIssuer) {
      response.writeHead(400, { 'content-type': 'text/plain; charset=utf-8' })
      response.end('Authorization callback rejected. Return to the terminal.')
      return
    }
    const error = requestUrl.searchParams.get('error')
    const code = requestUrl.searchParams.get('code')
    if (error || !code) {
      response.writeHead(400, { 'content-type': 'text/plain; charset=utf-8' })
      response.end('Authorization failed. Return to the terminal.')
      if (!settled) {
        settled = true
        reject?.(new Error(error ? `OAuth authorization failed: ${error}` : 'OAuth callback is incomplete.'))
      }
      return
    }
    response.writeHead(200, {
      'content-security-policy': "default-src 'none'",
      'content-type': 'text/plain; charset=utf-8',
      'x-content-type-options': 'nosniff',
    })
    response.end('Athlendra CLI connected. You may close this tab.')
    if (!settled) {
      settled = true
      settle?.({ code, state, issuer })
    }
  })

  await new Promise<void>((resolve, rejectListen) => {
    server.once('error', rejectListen)
    server.listen(0, '127.0.0.1', () => resolve())
  })
  const address = server.address() as AddressInfo
  const timeout = setTimeout(() => {
    if (settled) return
    settled = true
    reject?.(new Error('OAuth callback timed out.'))
    void closeServer(server).catch(() => undefined)
  }, expectation.timeoutMs ?? 300_000)
  return {
    redirectUri: `http://127.0.0.1:${address.port}/oauth/callback`,
    waitForCallback: () => callback,
    close: async () => {
      clearTimeout(timeout)
      if (!settled) {
        settled = true
        reject?.(new Error('OAuth callback cancelled.'))
      }
      await closeServer(server)
    },
  }
}

export const loopbackCallbackServer: CallbackServer = {
  start: startLoopbackCallbackServer,
}
