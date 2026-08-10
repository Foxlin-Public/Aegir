# Integration: Go

> **Not released in Beta-1.** The Go source in this repository can be read and built locally,
> but the module path `foxlin/aegir-security-go` has no domain, so `go get` cannot resolve it and
> there is nothing to depend on. Beta-1 ships .NET, Node and Python. This guide describes
> source-only usage.

## Module

- module: `foxlin/aegir-security-go`
- version: `0.1.1-beta.1`

## What The Go SDK Covers

Use the Go SDK when you want hosted Aegir Beta-1 access from Go services, CLI tooling, or lightweight automation.

The Beta-1 Go package includes:

- `AegirSecurityClient`
- safe envelopes
- budget envelopes
- in-memory agent-to-agent helpers
- trust-core signing and verification helpers
- diagnostics hooks
- canonical error semantics

## Required Configuration

The Go client needs:

- `AEGIR_BASE_URL`
- `AEGIR_DEVELOPER_KEY` - in the form `devKeyId:secret`

`AEGIR_CONFIG_KEY` is retired and must not be set. The API no longer accepts it as a credential, and it still opens pre-authentication routes - holding it in a client process is exposure with no benefit.

## Beta-1 Operations

- `ScanIdentity`
- `GetIdentityGraph`
- `GetIdentityGraphJSON`
- `GetExposureSummary`
- `PerformAction`
- `ReverseAction`
- `GetActionHistory`

## Integration Notes

For Beta-1, the Go module stays close to the hosted Aegir API surface and shared error model. That helps keep parity with the other language bindings.

## Example Pattern

The expected Go flow is:

1. initialize `AegirSecurityClient`
2. call the hosted Beta-1 operation you need
3. inspect the typed result
4. handle canonical Aegir client errors in your service or CLI logs

## Beta-1 Boundary

The Go package exposes the hosted/public Beta-1 surface only.
