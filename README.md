# Athlendra CLI

Command-line access to the Athlendra agent REST API. Browser OAuth connects your account, and the operating-system keyring stores credentials.

## Install

Requires Node.js 22.18 or newer on Node 22, or Node.js 24.12 or newer. Install into a user-owned directory:

```sh
npm install --prefix "$HOME/.local/share/athlendra" --omit=dev @athlendra/cli
export PATH="$HOME/.local/share/athlendra/node_modules/.bin:$PATH"
athlendra --version
athlendra --origin https://api.athlendra.com connect
```

Keep the PATH export in your shell profile. Connect opens browser OAuth; sign in as a coach and approve the requested access.

## Build from source

```sh
npm ci
npm run typecheck
npm test
npm pack
```

The generated operation manifest comes from the Athlendra API catalog. Schema parity checks run in the application repository; this repository tests CLI behavior independently.

Source is provided for inspection and release provenance. The package remains UNLICENSED.

## Origin configuration

This release does not assume a production domain. Pass the deployed Athlendra API origin explicitly or set it in the environment:

```bash
athlendra --origin https://your-athlendra-api.example connect
export ATHLENDRA_ORIGIN=https://your-athlendra-api.example
```

Remote origins must use HTTPS. HTTP is accepted only for loopback development addresses.
OAuth protected-resource discovery may select a separate HTTPS Athlendra authorization-server origin. REST calls continue to use the configured API origin.

## Authentication

`connect` opens browser OAuth, registers an ephemeral loopback callback, uses S256 PKCE, and stores the resulting client and token data in the operating-system keyring. The CLI never falls back to a plaintext token file.

```bash
athlendra --origin https://your-athlendra-api.example connect
athlendra --origin https://your-athlendra-api.example connect --profile full
athlendra --origin https://your-athlendra-api.example connect --scope clients:read --scope sessions:read
```

Default access includes released read scopes. `--profile full` includes released write scopes. Repeated `--scope` flags request an explicit least-privilege set. Running `connect` again starts fresh consent. An origin-specific cross-process lock serializes connect, call, and logout credential changes. Reconnect stores the new grant in an origin-specific keyring recovery account before revoking the prior grant and promoting the new credentials. Stable, non-secret grant identity distinguishes one OAuth grant from its rotating token snapshots. Interrupted reconnects recover or use that staged grant without writing tokens to disk. `logout` revokes every primary or staged grant before deleting any local credential. A revocation failure keeps the credentials and exits nonzero.

Refresh attempts to store each rotated snapshot in every tracked keyring replica for the same grant. One successful write keeps the grant usable; later recovery repairs or removes failed replicas. If every keyring write fails after the provider rotates the token, no secure local copy can be recovered. The CLI reports the non-secret client ID so the user can revoke that client and reconnect. It never prints tokens or writes a plaintext fallback.

The process lock protects credential integrity, but stale PID reuse can temporarily block commands until that process exits. Process termination after token issuance but before the first keyring staging write can leave a remote grant that requires service-side revocation.

If the keyring is unavailable, use a host's native MCP OAuth. Advanced users may put an Athlendra PAT in the caller's secret manager. Never paste a token into a prompt.

## Commands

```bash
athlendra operations
athlendra call find_clients --input '{"query":"Alex"}'
athlendra call get_client_schedule --input-file request.json --json
athlendra logout
```

`operations` includes generated descriptions, scopes, conditional scopes, least-privilege guidance, and input examples. Calls refresh shortly before expiry. OAuth and operation requests reject HTTP redirects so codes, verifiers, tokens, and operation bodies stay on the configured endpoint.

A transport retry keeps the same generated idempotency key. Confirmation-required output prints the same-origin confirmation URL, confirmation ID, and effective idempotency key needed to repeat the input after approval. Supply those values in the repeated JSON input. The CLI never saves the business input. Human-readable output prints the operation summary; `--json` prints the complete stable success or error envelope. Operation failures exit nonzero.
