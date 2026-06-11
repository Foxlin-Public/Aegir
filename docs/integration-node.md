# Integration: Node

## Package

- package: `@foxlin_industries/aegir-security`
- version: `0.1.1-beta-1`

## What The Node SDK Covers

Use the Node SDK when you want to call the hosted Aegir Beta-1 API from Node services, edge tooling, automation scripts, or MCP-adjacent JavaScript runtimes.

The Beta-1 Node package includes:

- the hosted Aegir client
- canonical error handling
- diagnostics hooks
- safe envelopes
- budget envelopes
- in-memory agent-to-agent helpers
- trust-core signing and verification helpers

## Required Configuration

The Node client needs:

- `AEGIR_BASE_URL`
- `AEGIR_CONFIG_KEY`
- `AEGIR_DEVELOPER_KEY`

These values define the hosted Aegir endpoint and the developer credentials for the integration.

## Beta-1 Operations

The public Beta-1 operations are:

- `scanIdentity`
- `getIdentityGraph`
- `getIdentityGraphJson`
- `getExposureSummary`
- `performAction`
- `reverseAction`
- `getActionHistory`

## Typical Request Lifecycle

In a normal Beta-1 Node flow:

1. construct the client with the hosted API base URL and credentials
2. call a read or action operation
3. inspect the returned object
4. catch canonical Aegir client errors and log the provided error code or correlation metadata
5. forward only safe, application-level error messages to callers

## Error Handling

The Node SDK treats the hosted Aegir API as a remote dependency. For Beta-1, your integration should plan for:

- missing or invalid configuration
- network or transport failures
- API-side rejections with canonical Aegir error semantics
- malformed application payloads

Use the canonical error shape consistently in your app logs and monitoring so operators can distinguish Aegir policy rejections from local application bugs.

## Retries

For Beta-1:

- retries are safest on read-oriented operations
- mutation operations should be retried only with clear idempotency rules in your own application
- log the original failure before retrying so you preserve the Aegir error context

## Example

See [../examples/npm/index.mjs](../examples/npm/index.mjs).

## Beta-1 Boundary

The Node package in this repo exposes only the current hosted/public Beta-1 surface. It does not include unpublished Foxlin runtime operations or Beta-2 capabilities.
