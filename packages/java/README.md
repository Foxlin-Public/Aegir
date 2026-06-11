# Aegir Security Java Package

`cloud.foxlin:aegir-security` is the Beta-1 Java SDK for Aegir Security.

## Installation

```xml
<dependency>
  <groupId>cloud.foxlin</groupId>
  <artifactId>aegir-security</artifactId>
  <version>0.1.1-beta-1</version>
</dependency>
```

## Quickstart

```java
import cloud.foxlin.aegir.security.*;

AegirSecurityClient client = new AegirSecurityClient(
    "https://api.aegir.foxlinindustries.com/apis",
    System.getenv("AEGIR_CONFIG_KEY"),
    System.getenv("AEGIR_DEVELOPER_KEY"));

try {
    SecurityModels.ScanIdentityResult scan = client.scanIdentity("developer:dev_123");
    SecurityModels.IdentityGraphSnapshot graph = client.getIdentityGraph("developer:dev_123");
    SecurityModels.IdentityActionRecord action = client.performAction(
        new PerformIdentityActionRequest(
            "developer:dev_123",
            SecurityModels.IdentityActionType.LockIdentity,
            null,
            "Manual containment review."));
} catch (AegirSecurityError ex) {
    System.err.println(ex.getStatus() + " " + ex.getErrorCode());
}
```

## API Reference

See [Beta-1 API Reference](../../docs/api-reference-0.1.1-beta-1.md).

## Supported Operations

- `scanIdentity`
- `getIdentityGraph`
- `getIdentityGraphJson`
- `getExposureSummary`
- `performAction`
- `reverseAction`
- `getActionHistory`
- `PortableSecurity` signing and safe-envelope helpers
- `PortableSecurity.InMemoryBudgetEnvelopeService`
- `PortableSecurity.InMemoryAgentToAgentProtocol`

## Error Model

HTTP failures throw `AegirSecurityError` with `getStatus()`, `getCode()`, `getErrorCode()`, `getCorrelationId()`, and `getBody()`. Budget exhaustion throws `PortableSecurity.BudgetExhaustedError`.

## Diagnostics Hooks

`AegirSecurityClient` accepts `AegirDiagnosticsHooks`. Java uses nested event types: `AegirDiagnosticsHooks.LogEntry`, `AegirDiagnosticsHooks.MetricEvent`, and `AegirDiagnosticsHooks.TraceEvent`.

## Budget Options

`PortableSecurity.InMemoryBudgetEnvelopeService` accepts `PortableSecurity.BudgetEnvelopeOptions`.

Defaults:

- `identityScanLimit`: `25`
- `externalLookupLimit`: `50`
- `connectionGraphRebuildLimit`: `10`
- `windowMs`: `60000`
