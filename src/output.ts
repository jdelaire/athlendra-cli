function sorted(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sorted)
  if (value === null || typeof value !== 'object') return value
  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
      .map(([key, child]) => [key, sorted(child)]),
  )
}

export function stableJson(value: unknown): string {
  return JSON.stringify(sorted(value))
}

export function formatConnected(
  origin: string,
  scopes: readonly string[],
  _sensitiveValues?: unknown,
): string {
  return `Connection: ${origin}\nScopes: ${scopes.join(', ')}\nConnected successfully.\n`
}

export function formatOperationResult(envelope: unknown, json: boolean): string {
  if (json) return `${stableJson(envelope)}\n`
  if (envelope === null || typeof envelope !== 'object') return 'Operation completed.\n'
  const result = envelope as { summary?: unknown; deepLink?: unknown }
  const summary = typeof result.summary === 'string' ? result.summary : 'Operation completed.'
  const deepLink = typeof result.deepLink === 'string' ? `\n${result.deepLink}` : ''
  return `${summary}${deepLink}\n`
}

interface PrintableOperationError {
  origin: string
  envelope: {
    error: {
      code: string
      message: string
      details?: Record<string, unknown>
    }
  }
  idempotencyKey?: string
}

export function printableIdempotencyKey(value: unknown): string | undefined {
  return typeof value === 'string' && /^[A-Za-z0-9._:-]{8,128}$/.test(value)
    ? value
    : undefined
}

function safeConfirmationUrl(value: unknown, origin: string): string | undefined {
  if (typeof value !== 'string') return undefined
  try {
    const url = new URL(value)
    return url.origin === origin ? url.toString() : undefined
  } catch {
    return undefined
  }
}

export function formatOperationError(error: PrintableOperationError): string {
  const details = error.envelope.error.details ?? {}
  const confirmationId = typeof details.confirmationId === 'string'
    && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(details.confirmationId)
    ? details.confirmationId
    : undefined
  const confirmationUrl = safeConfirmationUrl(details.confirmationUrl, error.origin)
  const idempotencyKey = printableIdempotencyKey(error.idempotencyKey)
  const lines = [`${error.envelope.error.code}: ${error.envelope.error.message}`]
  if (confirmationUrl) lines.push(`Confirmation: ${confirmationUrl}`)
  if (idempotencyKey) lines.push(`Idempotency key: ${idempotencyKey}`)
  if (confirmationId && idempotencyKey) {
    lines.push(
      `After approval, repeat the same command input with "idempotencyKey":"${idempotencyKey}" and "confirmationId":"${confirmationId}".`,
    )
  }
  return `${lines.join('\n')}\n`
}
