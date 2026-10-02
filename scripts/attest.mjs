import { createHash } from 'node:crypto'
import { readFile, writeFile } from 'node:fs/promises'
import { createRequire } from 'node:module'

if (process.env.GITHUB_ACTIONS !== 'true' || process.env.RUNNER_ENVIRONMENT !== 'github-hosted') {
  throw new Error('Provenance must be generated on a GitHub-hosted Actions runner.')
}
if (!process.env.npm_execpath) throw new Error('Run this script through npm run attest.')

const require = createRequire(process.env.npm_execpath)
const { generateProvenance } = require('libnpmpublish/lib/provenance.js')
const packageArgument = require('npm-package-arg')
const [tarballPath, bundlePath] = process.argv.slice(2)
if (!tarballPath || !bundlePath) throw new Error('Provide tarball and provenance bundle paths.')

const manifest = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'))
const tarball = await readFile(tarballPath)
const subject = {
  name: packageArgument.toPurl(packageArgument.resolve(manifest.name, manifest.version)),
  digest: { sha512: createHash('sha512').update(tarball).digest('hex') },
}
const bundle = await generateProvenance([subject], {})
await writeFile(bundlePath, JSON.stringify(bundle) + '\n')
console.log(`Signed ${manifest.name}@${manifest.version} with GitHub Actions provenance.`)
