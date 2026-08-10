# Aegir Security 0.1.1-beta.1 Release Notes

## Summary

Beta-1 finalizes the compact public SDK surface for Aegir Security and aligns C#, TypeScript, Java, Python, and Go bindings.

## Changes Since Alpha

- Reduced the public C# surface to the Beta-1 SDK contract.
- Added full cross-language DTO, enum, diagnostics, error-code, budget, portable crypto, and A2A parity.
- Added typed Java DTOs and enums for graph, exposure, action, and error-code models.
- Added typed Python and Go enum/error-code bindings.
- Added typed TypeScript unions for all public enum-backed model fields.
- Aligned budget options and defaults across all SDKs.

## Finalized Public API Surface

Public identity operations are scan identity, get graph, get graph JSON, get exposure summary, perform action, reverse action, and get action history. Portable helpers cover safe envelopes, trust-core signing/verification, budget envelopes, and A2A protocol messages.

See [Public API Surface](public-api-surface-final-0.1.1-beta-1.md) and [API Reference](api-reference-0.1.1-beta-1.md).

## Cross-Language Parity

The cross-language parity matrix is complete for C#, TypeScript, Java, Python, and Go. DTO shapes, enum values, error-code behavior, diagnostics event shapes, portable crypto helpers, budget options, and A2A protocol types are aligned.

## Security Improvements

- Public safe-envelope validation is available in all SDKs.
- Trust-core challenge, proof-receipt, and identity-token helpers are available in all SDKs.
- Budget envelopes enforce operational controls consistently across SDKs.
- Diagnostics hooks expose request lifecycle logs, metrics, and traces.

## Packaging Readiness

Package versions are aligned to `0.1.1-beta.1` across NuGet, npm, Maven, PyPI, and Go. Package-specific publishing validation continues under the packaging readiness checklist.
