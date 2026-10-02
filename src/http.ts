export class CliError extends Error {
  readonly exitCode: number
  reported = false

  constructor(message: string, exitCode = 1) {
    super(message)
    this.name = 'CliError'
    this.exitCode = exitCode
  }
}

export async function postWithoutRedirect(
  fetcher: typeof globalThis.fetch,
  input: URL | RequestInfo,
  init: Omit<RequestInit, 'method' | 'redirect'>,
  context: string,
): Promise<Response> {
  const response = await fetcher(input, { ...init, method: 'POST', redirect: 'manual' })
  if ((response.status >= 300 && response.status < 400) || response.type === 'opaqueredirect') {
    throw new CliError(`${context} refused an HTTP redirect.`)
  }
  return response
}

export async function readJsonResponse(response: Response, context: string): Promise<unknown> {
  try {
    return await response.json()
  } catch {
    throw new CliError(`${context} returned invalid JSON.`)
  }
}

export function objectValue(value: unknown, context: string): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new CliError(`${context} returned an invalid response.`)
  }
  return value as Record<string, unknown>
}

export function requireString(
  object: Record<string, unknown>,
  key: string,
  context: string,
): string {
  const value = object[key]
  if (typeof value !== 'string' || value.length === 0) {
    throw new CliError(`${context} omitted ${key}.`)
  }
  return value
}
