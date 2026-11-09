# Changelog

## Unreleased — AEG-RC1-R004

- Retire keyless signing/verification authority with fail-closed compatibility stubs.
- Remove the custom digest; expose clearly named standard SHA-256 integrity utilities.
- Reject signed portable envelopes and mark unsigned validation as integrity only.
- Add shared digest vectors and historical-forgery rejection coverage across language copies.
- Preserve server keyed receipt/message contracts; no SDK release or publication.

## 0.1.1-beta.1

- move the canonical Aegir application host to `https://aegir.foxlinindustries.com`
- move the canonical Aegir API host to `https://api.aegir.foxlinindustries.com/apis`
- prepare the coordinated Beta-1 SDK refresh for NuGet, npm, and Foxlin-Public sync

## 0.1.0-beta-1

- initial standalone Beta-1 SDK repository
- vendored Beta-1 Node, Java, Python, and Go SDK package sources
- .NET Beta-1 package documentation and example consumer
- wrapped installer scripts for local Beta-1 bootstrap
- local Beta-1 MCP stdio wrapper over the hosted public Aegir API surface
- Beta-1 repository and integration documentation
