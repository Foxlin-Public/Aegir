# Aegir Security Python Package

`foxlin-aegir-security` is the Beta-1 Python SDK for Aegir Security.

## Installation

```bash
python -m pip install foxlin-aegir-security==0.1.1-beta.1
```

## Quickstart

```python
from foxlin_aegir_security import (
    AegirDiagnosticsHooks,
    AegirSecurityClient,
    AegirSecurityError,
    IdentityActionType,
    PerformIdentityActionRequest,
)

client = AegirSecurityClient(
    base_url="https://api.aegir.foxlinindustries.com/apis",
    config_key="sample-config-key",
    developer_key="sample-developer-key",
    diagnostics_hooks=AegirDiagnosticsHooks(
        log=lambda entry: print(entry["eventName"]),
        metric=lambda event: print(event["metricName"]),
        trace=lambda event: print(event["traceName"]),
    ),
)

try:
    scan = client.scanIdentity("developer:dev_123")
    graph = client.getIdentityGraph("developer:dev_123")
    action = client.performAction(
        PerformIdentityActionRequest(
            subjectId="developer:dev_123",
            actionType=IdentityActionType.LockIdentity,
            reason="Manual containment review.",
        )
    )
except AegirSecurityError as ex:
    print(ex.status, ex.code, ex.correlationId)
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

HTTP failures raise `AegirSecurityError` with `status`, typed `code`, `correlationId`, and `body`. Budget exhaustion raises `BudgetExhaustedError`.

## Diagnostics Hooks

Pass `AegirDiagnosticsHooks` with `log`, `metric`, and `trace` callbacks.

## Budget Options

`InMemoryBudgetEnvelopeService` accepts `BudgetEnvelopeOptions`.

Defaults:

- `identityScanLimit`: `25`
- `externalLookupLimit`: `50`
- `connectionGraphRebuildLimit`: `10`
- `windowMs`: `60000`
