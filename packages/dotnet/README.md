# .NET SDK

Foxlin Industries. The D1 developer integration is unreleased source in
[integration/README.md](integration/README.md). It provides actual current read/write
checks, callback enforcement, authentication and durable event consumers without
requiring the private server engine.

Existing published-package metadata is retained in `../../sdk-manifest.json`.
The legacy example at `../../examples/dotnet/NuGetConsumer.csproj` pins the locally
cached `Foxlin.Aegir.Security` package at `0.1.1-beta.1`; it is a separate existing
surface compatibility check and does not contain the D1 source integration.
Registry publication was not performed or re-certified in this pass. Do not assume
that the source integration exists in an older package release.

Build the integration project and runnable example locally as described in its guide.
The common [developer integration guide](../../docs/developer-integration-v1.md)
documents supported limits, secure configuration, reauthentication and recovery.
