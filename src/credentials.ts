import { AsyncEntry } from '@napi-rs/keyring'
import type { StoredCredentials } from './auth.js'
import { CliError } from './http.js'

export const KEYRING_SERVICE = 'coachforge-cli'

export interface CredentialStore {
  assertAvailable(): Promise<void>
  get(account: string): Promise<StoredCredentials | null>
  set(account: string, credentials: StoredCredentials): Promise<void>
  delete(account: string): Promise<boolean>
}

export function keyringUnavailable(): CliError {
  return new CliError(
    'OS keyring unavailable. Use native MCP OAuth, or store an advanced PAT in the caller secret manager.',
  )
}

function entry(account: string): AsyncEntry {
  return new AsyncEntry(KEYRING_SERVICE, account)
}

export const nativeCredentialStore: CredentialStore = {
  async assertAvailable() {
    try {
      await entry('__availability_check__').getPassword()
    } catch {
      throw keyringUnavailable()
    }
  },
  async get(account) {
    try {
      const value = await entry(account).getPassword()
      if (!value) return null
      return JSON.parse(value) as StoredCredentials
    } catch {
      throw keyringUnavailable()
    }
  },
  async set(account, credentials) {
    try {
      await entry(account).setPassword(JSON.stringify(credentials))
    } catch {
      throw keyringUnavailable()
    }
  },
  async delete(account) {
    try {
      return await entry(account).deleteCredential()
    } catch {
      throw keyringUnavailable()
    }
  },
}
