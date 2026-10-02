import { describe, expect, it } from 'vitest'
import {
  formatConnected,
  formatOperationError,
  formatOperationResult,
  stableJson,
} from '../src/output'

describe('CLI output', () => {
  it('prints only connection label, scopes, and success text', () => {
    const text = formatConnected('https://athlendra.example.test', ['clients:read'], {
      accessToken: 'ACCESS-SECRET', refreshToken: 'REFRESH-SECRET', clientId: 'CLIENT-SECRET',
    })
    expect(text).toBe('Connection: https://athlendra.example.test\nScopes: clients:read\nConnected successfully.\n')
    expect(text).not.toContain('SECRET')
  })

  it('prints human summary by default without dumping envelope data', () => {
    const envelope = { summary: 'Found one client.', data: { private: 'hidden' }, deepLink: 'https://example.test/x' }
    expect(formatOperationResult(envelope, false)).toBe('Found one client.\nhttps://example.test/x\n')
  })

  it('prints full stable JSON envelope with sorted object keys', () => {
    const envelope = { summary: 'Done.', data: { z: 1, a: { y: 2, b: 3 } } }
    expect(formatOperationResult(envelope, true)).toBe(`${stableJson(envelope)}\n`)
    expect(stableJson(envelope)).toBe('{"data":{"a":{"b":3,"y":2},"z":1},"summary":"Done."}')
  })

  it('prints safe confirmation retry instructions without business input', () => {
    const text = formatOperationError({
      origin: 'https://athlendra.example.test',
      envelope: {
        error: {
          code: 'confirmation_required', message: 'Coach confirmation is required', retryable: false,
          details: {
            confirmationId: '11111111-1111-4111-8111-111111111111',
            confirmationUrl: 'https://athlendra.example.test/confirm/11111111-1111-4111-8111-111111111111',
          },
        },
      },
      idempotencyKey: 'cli-key-12345678',
    })
    expect(text).toContain('https://athlendra.example.test/confirm/11111111-1111-4111-8111-111111111111')
    expect(text).toContain('cli-key-12345678')
    expect(text).toContain('"confirmationId":"11111111-1111-4111-8111-111111111111"')

    const unsafe = formatOperationError({
      origin: 'https://athlendra.example.test',
      envelope: {
        error: {
          code: 'confirmation_required', message: 'Confirm.', retryable: false,
          details: { confirmationUrl: 'https://evil.test/steal', confirmationId: 'bad\nterminal' },
        },
      },
      idempotencyKey: 'bad\nterminal',
    })
    expect(unsafe).not.toContain('evil.test')
    expect(unsafe).not.toContain('bad\nterminal')
  })
})
