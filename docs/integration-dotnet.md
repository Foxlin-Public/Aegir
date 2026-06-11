# Integration: .NET

## Package

- package: `Foxlin.Aegir.Security`
- version: `0.1.1-beta-1`

## What The .NET SDK Covers

Use the `.NET` SDK when you want typed access to the hosted Aegir Beta-1 surface from ASP.NET, worker services, automation jobs, or other `.NET` applications.

The Beta-1 `.NET` package includes:

- the hosted Aegir API client
- typed request and response models
- canonical client error handling
- diagnostics hooks
- trust-core helper utilities
- safe-envelope and budget-envelope helpers
- access-control evaluation helpers

## Required Configuration

The `.NET` client needs:

- `AEGIR_BASE_URL`
- `AEGIR_CONFIG_KEY`
- `AEGIR_DEVELOPER_KEY`

These values identify the hosted Aegir endpoint and the developer credentials used for Beta-1 access.

## Beta-1 Operations

The public Beta-1 operations are:

- `ScanIdentityAsync`
- `GetIdentityGraphAsync`
- `GetIdentityGraphJsonAsync`
- `GetExposureSummaryAsync`
- `PerformActionAsync`
- `ReverseActionAsync`
- `GetActionHistoryAsync`

## Access Control Helpers

The `.NET` package also includes:

- `AegirAccessLevel`
- `AegirAccessScope`
- `AegirAccessGrant`
- `AegirAccessDecision`
- `AegirAccessPolicyEvaluator`

These helpers let you evaluate `read_only`, `partial_control`, and `full_control` access patterns inside your own application without inventing a second access model.

## Typical Request Lifecycle

In a normal Beta-1 flow:

1. initialize the client with the hosted API base URL and your Aegir credentials
2. call one of the Beta-1 operations
3. inspect the typed result
4. handle canonical client exceptions when the request is rejected or malformed
5. optionally record diagnostics or inspect action history

## Error Handling

The `.NET` package uses canonical Aegir client exceptions for API-side failures. In Beta-1, your integration should assume these broad categories:

- configuration failures, such as missing base URL or keys
- transport or network failures
- API rejections with Aegir error metadata
- malformed request payloads from the calling application

Your application should treat Aegir API calls as external service calls:

- validate inputs before sending them
- log the Aegir correlation or diagnostic data you receive
- surface actionable errors to operators without exposing secrets

## Retries

The SDK does not hide the fact that the hosted Aegir API is a remote dependency. For Beta-1:

- retry only idempotent read-style operations when your platform policy allows it
- avoid blind retries for mutation-style operations such as `PerformActionAsync` or `ReverseActionAsync`
- capture diagnostics before retrying so you can distinguish transport issues from rejected requests

## Example

See [../examples/dotnet/Program.cs](../examples/dotnet/Program.cs).

## Beta-1 Boundary

The `.NET` SDK in this repo is limited to the current hosted/public Beta-1 surface. It does not expose Beta-2 operations or private Foxlin runtime features.
