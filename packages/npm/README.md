# Aegir Security NPM Package

`@foxlin_industries/aegir-security` is the Beta-1 TypeScript SDK for Aegir Security.

## Installation

```bash
npm install @foxlin_industries/aegir-security@0.1.1-beta-1
```

## Quickstart

```ts
import {
  AegirSecurityClient,
  AegirSecurityError,
  type PerformIdentityActionRequest
} from "@foxlin_industries/aegir-security";

const client = new AegirSecurityClient({
  baseUrl: "https://api.aegir.foxlinindustries.com/apis",
  configKey: process.env.AEGIR_CONFIG_KEY,
  developerKey: process.env.AEGIR_DEVELOPER_KEY,
  diagnosticsHooks: {
    log: (entry) => console.log(entry.eventName),
    metric: (event) => console.log(event.metricName),
    trace: (event) => console.log(event.traceName)
  }
});

try {
  const scan = await client.scanIdentity("developer:dev_123");
  const graph = await client.getIdentityGraph("developer:dev_123");
  const actionRequest: PerformIdentityActionRequest = {
    subjectId: "developer:dev_123",
    actionType: "LockIdentity",
    reason: "Manual containment review."
  };
  const action = await client.performAction(actionRequest);
} catch (error) {
  if (error instanceof AegirSecurityError) {
    console.error(error.status, error.code, error.correlationId);
  }
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
- portable crypto helpers
- safe envelope helpers
- `InMemoryBudgetEnvelopeService`
- `InMemoryAgentToAgentProtocol`

## Error Model

HTTP failures throw `AegirSecurityError` with `status`, typed `code`, `correlationId`, and `body`. Budget exhaustion throws `BudgetExhaustedError`.

## Diagnostics Hooks

Pass `diagnosticsHooks` with `log`, `metric`, and `trace` callbacks. Event shapes are `AegirLogEntry`, `AegirMetricEvent`, and `AegirTraceEvent`.

## Budget Options

`InMemoryBudgetEnvelopeService` accepts `BudgetEnvelopeOptions`.

Defaults:

- `identityScanLimit`: `25`
- `externalLookupLimit`: `50`
- `connectionGraphRebuildLimit`: `10`
- `windowMs`: `60000`
