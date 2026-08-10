# Aegir Security Go Package

`foxlin/aegir-security-go` is the Beta-1 Go SDK for Aegir Security.

## Installation

```bash
go get foxlin/aegir-security-go@v0.1.1-beta.1
```

## Quickstart

```go
package main

import (
	"fmt"
	"net/http"

	aegirsecurity "foxlin/aegir-security-go"
)

func main() {
	client := aegirsecurity.NewAegirSecurityClientWithOptions(aegirsecurity.ClientOptions{
		BaseURL:      "https://api.aegir.foxlinindustries.com/apis",
		ConfigKey:    "sample-config-key",
		DeveloperKey: "sample-developer-key",
		HTTPClient:   http.DefaultClient,
		Diagnostics: &aegirsecurity.DiagnosticsHooks{
			Log: func(entry aegirsecurity.LogEntry) { fmt.Println(entry.EventName) },
		},
	})

	scan, err := client.ScanIdentity("developer:dev_123")
	if err != nil {
		if typed, ok := err.(*aegirsecurity.AegirSecurityError); ok {
			fmt.Println(typed.Status, typed.Code, typed.CorrelationID)
		}
		return
	}
	graph, _ := client.GetIdentityGraph(scan.SubjectID)
	action, _ := client.PerformAction(aegirsecurity.PerformIdentityActionRequest{
		SubjectID:  scan.SubjectID,
		ActionType: aegirsecurity.IdentityActionTypeLockIdentity,
	})
	_, _ = graph, action
}
```

## API Reference

See [Beta-1 API Reference](../../docs/api-reference-0.1.1-beta-1.md).

## Supported Operations

- `ScanIdentity`
- `GetIdentityGraph`
- `GetIdentityGraphJSON`
- `GetExposureSummary`
- `PerformAction`
- `ReverseAction`
- `GetActionHistory`
- portable crypto helpers
- safe envelope helpers
- `NewInMemoryBudgetEnvelopeService`
- `NewInMemoryAgentToAgentProtocol`

## Error Model

HTTP failures return `*AegirSecurityError` with `Status`, typed `Code`, `CorrelationID`, and `Body`. Budget exhaustion returns `*BudgetExhaustedError`.

## Diagnostics Hooks

`DiagnosticsHooks` accepts `Log`, `Metric`, and `Trace` callbacks. Go uses idiomatic `LogEntry`, `MetricEvent`, and `TraceEvent` names, with `AegirLogEntry`, `AegirMetricEvent`, and `AegirTraceEvent` aliases.

## Budget Options

`NewInMemoryBudgetEnvelopeService` accepts `BudgetEnvelopeOptions`.

Defaults:

- `IdentityScanLimit`: `25`
- `ExternalLookupLimit`: `50`
- `ConnectionGraphRebuildLimit`: `10`
- `WindowMS`: `60000`
