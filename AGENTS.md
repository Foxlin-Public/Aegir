# AGENTS.md

Instructions for coding agents working in this repository. Humans should read
[CONTRIBUTING.md](CONTRIBUTING.md) as well; the two agree, but this file states the parts an agent
gets wrong without being told.

For an index of the repository's documentation, see [llms.txt](llms.txt).

## What this repository is

The public Beta-1 SDK distribution for **Aegir Security**, the identity and authorization engine
from **Foxlin Industries**. It contains client packages for .NET, Node and Python, integration
documentation, examples, and a local stdio MCP wrapper.

It is **not** the Aegir product runtime. The API host, database schema, migrations, deployment
automation and internal admin code live elsewhere and are deliberately absent. If a task seems to
require editing the server, the task is in the wrong repository â€” say so rather than approximating
the server here.

## Ownership and attribution

Every copyright notice, licence, footer and package manifest names **Foxlin Industries**. Aegir is
a Foxlin Industries engine.

Do not attribute this work to any third party, jointly or otherwise. A joint copyright line is not
cosmetic â€” it reads as a written admission of shared ownership. Treat a wrong or joint notice as a
release-blocking defect. Do not copy an entity name from a neighbouring file; if ownership is
ambiguous, ask.

`PatchWarden LLC` is a separate entity and must not appear in this repository.

## Facts that are easy to get wrong

`sdk-manifest.json` is the machine-readable source of truth. Where prose disagrees with it, the
manifest wins and the prose is a bug.

**Distribution follows sdk-manifest.json.** The current working source is `0.1.2-beta.1` (PyPI spelling `0.1.2b1`), unreleased in all five integration ecosystems. The manifest separately records historical published .NET/Node versions; Python/Java/Go are source-only according to that recorded metadata. Do not claim current registry availability without checking it. Do not rename versioned documentation filenames or change package versions for prose consistency.

**Retired keyless helpers are not cryptography.** Signing helpers throw (Go panics), verification rejects and the custom digest is removed. The SHA-256 exact-byte integrity utility is unauthenticated. Native PQC interoperability remains separate. Existing actual crypto uses ML-KEM-768/AES-256-GCM protected payloads, ML-DSA-65 origins/receipts and HS256 tokens; TLS and envelope claims stay separate.

**`AEGIR_CONFIG_KEY` is not a client credential.** It is a Beta-1 transitional server-side value,
is no longer accepted on identity-bearing routes, and still opens pre-authentication routes â€” so
putting it in a client process is exposure with no benefit. It must not appear in examples, MCP
environment files, documentation or tests. Authenticate with a developer key exchanged for a
narrowed token, or with an agent key.

## Conventions that carry meaning

**Open the transaction before the protected operation.** Every example and guide does this in that
order, and it is not stylistic: it is what makes a refused or abandoned attempt as auditable as a
successful one. Do not reorder it for brevity.

**Prefer a narrowed token to a developer key.** A narrowed token carries only the scopes requested
and expires; a developer key does neither.

**An agent is a principal, not a setting.** It has its own credential, scopes and revocation. An
agent can never register another agent or widen its own authority. Do not write examples that
imply otherwise.

**Authorities are separate on purpose.** `transaction:read` is audit authority. It never implies
`identity:resolve` (resolving a principal to a person) or `protected:decrypt`. Do not collapse
them when simplifying an example.

**An agent key is returned once.** Examples must show it being captured at registration, never
re-fetched.

## Build and test

Run the checks for whatever you touched. There is no repository-wide test command.

```bash
# Node SDK  (packages/npm)
npm install && npm run build && npm test

# MCP wrapper  (mcp)
npm install && npm test

# Python SDK  (packages/python)
python -m pytest tests

# .NET example  (examples/dotnet) - compiles against the published package surface
dotnet build NuGetConsumer.csproj
```

The .NET example is the cheapest guard against breaking the public surface: it references the
package rather than project source, so it fails to compile if something it uses stops being
public. It once shipped broken with `error CS0122: 'IIdentitySecurityService' is inaccessible`.
With no credentials configured it prints the available surface and exits, so it is useful as a
compile check on its own. **Build it after any change to the .NET surface or its examples** â€” do
not assume a documentation-only edit is safe until you have checked whether it contains code.

`packages/python/tests/live_flow.py` talks to a real host and is not part of the offline suite.

## Editing documentation

- Update the manifest and the affected guides together. A capability documented in one language's
  guide and absent from the others is the most common defect here.
- Keep the cross-language binding matrix in step when an operation is added or renamed.
- Do not invent operations. If an operation is not in
  [public-api-surface-final-0.1.1-beta-1.md](docs/public-api-surface-final-0.1.1-beta-1.md), it is
  not part of the supported surface.
- Prefer stating what a thing does not do when that is the interesting part. Much of this
  repository's documentation exists to prevent a specific wrong assumption.

## Scope

Stay inside the Beta-1 public SDK surface. Do not add Beta-2 features, new trust or KYC models,
hosted deployment, infrastructure automation, or MCP tools beyond the twelve in the manifest.

## Do not

- Claim Java or Go are published, installable, or production-ready.
- Describe the trust-core helpers as cryptography, authentication or proof.
- Put `AEGIR_CONFIG_KEY`, a developer key, an agent key or any other secret in source, examples,
  environment samples, logs or documentation.
- Rename the versioned documentation files.
- Publish a package, create a tag, or create a release. Releases are coordinated deliberately;
  `npm pack` and equivalents are fine for local validation.
- Weaken a check to make something pass. If a test, gate or assertion fails, either fix the cause
  or report it â€” never lower the bar to obtain green. A passing signal that no longer means
  anything is worse than a failing one.
- State that something builds, passes or is published without having verified it. Name the command
  you ran and what it printed. "Appears to work" is not a result.
