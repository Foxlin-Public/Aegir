# Integration: Python

## Package

- package: `foxlin-aegir-security`
- version: `0.1.1-beta-1`

## What The Python SDK Covers

Use the Python SDK when you want hosted Aegir Beta-1 access from automation, data-processing jobs, scripting, or service integrations.

The Beta-1 Python package includes:

- `AegirSecurityClient`
- safe envelopes
- budget envelopes
- in-memory agent-to-agent helpers
- trust-core signing and verification helpers
- diagnostics hooks
- canonical error semantics

## Required Configuration

The Python client needs:

- `AEGIR_BASE_URL`
- `AEGIR_CONFIG_KEY`
- `AEGIR_DEVELOPER_KEY`

## Beta-1 Operations

- `scanIdentity`
- `getIdentityGraph`
- `getIdentityGraphJson`
- `getExposureSummary`
- `performAction`
- `reverseAction`
- `getActionHistory`

## Integration Notes

For Beta-1, the Python package is designed to stay close to the hosted Aegir API surface. That makes it easier to move between SDK and MCP usage without learning a second product model.

## Example Pattern

The expected Python flow is:

1. initialize `AegirSecurityClient`
2. call one of the hosted Beta-1 operations
3. inspect the returned object or JSON payload
4. handle canonical Aegir client errors in your automation or service logs

## Beta-1 Boundary

The Python package exposes the hosted/public Beta-1 surface only.
