import { describe, expect, it } from 'vitest'
import { nativeReconnectLock } from '../src/reconnect-lock'

describe('reconnect lock', () => {
  it('excludes a competing process and releases for the next reconnect', async () => {
    const origin = `https://lock-${process.pid}.example.test`
    const releaseFirst = await nativeReconnectLock.acquire(origin)
    try {
      await expect(nativeReconnectLock.acquire(origin)).rejects.toThrow(/already in progress/i)
    } finally {
      await releaseFirst()
    }

    const releaseNext = await nativeReconnectLock.acquire(origin)
    await releaseNext()
  })
})
