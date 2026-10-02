# Releases

The public repository contains CLI source, the generated operation manifest, CLI tests, and release tooling. Application code and its Git history stay in the private application repository. This repository is the public npm build source.

The release workflow pins npm 11.19.1 because the attestation script uses that version's bundled provenance implementation. The script signs the exact packed tarball using the same npm provenance generator as `npm publish --provenance`.

## First release

Trusted publishing requires an existing npm package. Run the workflow without publishing, download its `athlendra-cli-release` artifact, and install and test its exact tarball in an isolated prefix. Authenticate locally with `npm login`, then publish that tarball together with its GitHub-generated bundle:

```sh
npm publish ./athlendra-cli-0.1.0.tgz --access public --provenance-file ./provenance.sigstore
npm trust github @athlendra/cli --repo jdelaire/athlendra-cli --file release.yml --allow-publish --yes
```

Complete npm's browser and 2FA prompts. The first publication already carries provenance. No npm publishing token needs to be stored in GitHub.

## Later releases

Update the package version and CLI version together, sync the generated operation manifest, run checks, and commit. Push a matching `v<version>` tag, or run the release workflow with publishing enabled. npm authenticates the workflow through OIDC.

Verify the registry version and provenance, then install the registry package in a fresh isolated prefix and check its version, help, and operation listing. Update application installation docs only after the package is publicly available.
