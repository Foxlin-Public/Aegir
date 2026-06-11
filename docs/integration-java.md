# Integration: Java

## Package

- package: `cloud.foxlin:aegir-security`
- version: `0.1.1-beta-1`

## What The Java SDK Covers

Use the Java SDK when you want typed Beta-1 Aegir access from JVM services, batch jobs, or integration platforms.

The Beta-1 Java package includes:

- `cloud.foxlin.aegir.security.AegirSecurityClient`
- canonical client error handling
- diagnostics hooks
- portable trust-core helper utilities

## Required Configuration

The Java client needs:

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

For Beta-1, the Java package is intended to mirror the hosted API surface cleanly rather than introduce a Java-only abstraction layer. Treat it as a typed API client with shared Aegir error semantics and diagnostics.

## Example Pattern

The expected usage pattern is:

1. initialize `AegirSecurityClient`
2. call a hosted Beta-1 operation
3. inspect the returned data
4. handle canonical client errors and correlation metadata in your application logging

## Beta-1 Boundary

The Java package exposes the hosted/public Beta-1 surface only.
