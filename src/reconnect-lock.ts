import { createHash, randomUUID } from 'node:crypto'
import { lstat, mkdir, readFile, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir, userInfo } from 'node:os'
import { join } from 'node:path'
import { CliError } from './http.js'

export interface ReconnectLock {
  acquire(origin: string): Promise<() => Promise<void>>
}

const effectiveUid = typeof process.getuid === 'function' ? process.getuid() : undefined
const userNamespace = effectiveUid === undefined
  ? createHash('sha256').update(userInfo().username).digest('hex').slice(0, 16)
  : String(effectiveUid)
const lockRoot = join(tmpdir(), `coachforge-cli-reconnect-locks-${userNamespace}`)

async function prepareLockRoot(): Promise<void> {
  await mkdir(lockRoot, { recursive: true, mode: 0o700 })
  const metadata = await lstat(lockRoot)
  const wrongOwner = effectiveUid !== undefined && metadata.uid !== effectiveUid
  const openPermissions = effectiveUid !== undefined && (metadata.mode & 0o077) !== 0
  if (!metadata.isDirectory() || metadata.isSymbolicLink() || wrongOwner || openPermissions) {
    throw new CliError('Reconnect lock directory is not private to the current OS user.')
  }
}

function processIsRunning(pid: number): boolean {
  try {
    process.kill(pid, 0)
    return true
  } catch (caught) {
    return caught instanceof Error && 'code' in caught && caught.code === 'EPERM'
  }
}

async function removeStaleLock(path: string): Promise<boolean> {
  try {
    const owner = JSON.parse(await readFile(join(path, 'owner.json'), 'utf8')) as { pid?: unknown }
    if (typeof owner.pid === 'number' && Number.isInteger(owner.pid) && processIsRunning(owner.pid)) return false
  } catch {
    const metadata = await stat(path).catch(() => null)
    if (!metadata || Date.now() - metadata.mtimeMs < 30_000) return false
  }
  await rm(path, { recursive: true, force: true })
  return true
}

export const nativeReconnectLock: ReconnectLock = {
  async acquire(origin) {
    await prepareLockRoot()
    const path = join(lockRoot, createHash('sha256').update(origin).digest('hex'))
    const nonce = randomUUID()
    for (let attempt = 0; attempt < 2; attempt += 1) {
      try {
        await mkdir(path, { mode: 0o700 })
        await writeFile(
          join(path, 'owner.json'),
          JSON.stringify({ nonce, pid: process.pid }),
          { encoding: 'utf8', mode: 0o600 },
        )
        return async () => {
          try {
            const owner = JSON.parse(await readFile(join(path, 'owner.json'), 'utf8')) as { nonce?: unknown }
            if (owner.nonce === nonce) await rm(path, { recursive: true, force: true })
          } catch {
            // Lock is already gone or no longer belongs to this process.
          }
        }
      } catch (caught) {
        if (!(caught instanceof Error && 'code' in caught && caught.code === 'EEXIST')) {
          await rm(path, { recursive: true, force: true }).catch(() => undefined)
          throw new CliError('Could not acquire the reconnect lock.')
        }
        if (!(await removeStaleLock(path))) {
          throw new CliError('Reconnect already in progress for this origin.')
        }
      }
    }
    throw new CliError('Could not acquire the reconnect lock.')
  },
}
