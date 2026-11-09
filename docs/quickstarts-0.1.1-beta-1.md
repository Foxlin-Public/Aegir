# Aegir Quickstarts v0.1.1-beta.1

Each example demonstrates client construction, diagnostics hooks, `scanIdentity`, `getIdentityGraph`, `performAction`, and error handling.

## C# / .NET

```csharp
using Foxlin.Aegir.Auth.Models;
using Foxlin.Aegir.Auth.Services;

var client = new AegirSecurityHttpClient(new AegirSecurityClientOptions
{
    BaseUrl = "https://api.aegir.foxlinindustries.com/apis",
    DeveloperKey = Environment.GetEnvironmentVariable("AEGIR_DEVELOPER_KEY"),
    DiagnosticsSink = new ConsoleDiagnosticsSink()
});

try
{
    ScanIdentityResult scan = await client.ScanIdentityAsync("developer:dev_123");
    IdentityGraphSnapshot graph = await client.GetIdentityGraphAsync(scan.SubjectId);
    IdentityActionRecord action = await client.PerformActionAsync(
        new PerformIdentityActionRequest(scan.SubjectId, IdentityActionType.LockIdentity));

    Console.WriteLine($"{graph.GraphId} {action.ActionId}");
}
catch (AegirSecurityClientException ex)
{
    Console.WriteLine($"{ex.StatusCode} {ex.ErrorCode} {ex.CorrelationId}");
}

sealed class ConsoleDiagnosticsSink : IAegirClientDiagnosticsSink
{
    public ValueTask WriteLogAsync(AegirClientLogEntry entry, CancellationToken cancellationToken = default)
    {
        Console.WriteLine(entry.EventName);
        return ValueTask.CompletedTask;
    }

    public ValueTask WriteMetricAsync(AegirMetricEvent metric, CancellationToken cancellationToken = default)
    {
        Console.WriteLine(metric.MetricName);
        return ValueTask.CompletedTask;
    }

    public ValueTask WriteTraceAsync(AegirTraceEvent trace, CancellationToken cancellationToken = default)
    {
        Console.WriteLine(trace.TraceName);
        return ValueTask.CompletedTask;
    }
}
```

## TypeScript / npm

```ts
import {
  AegirSecurityClient,
  AegirSecurityError,
  type PerformIdentityActionRequest
} from "@foxlin_industries/aegir-security";

const client = new AegirSecurityClient({
  baseUrl: "https://api.aegir.foxlinindustries.com/apis",
  developerKey: process.env.AEGIR_DEVELOPER_KEY,
  diagnosticsHooks: {
    log: (entry) => console.log(entry.eventName),
    metric: (event) => console.log(event.metricName),
    trace: (event) => console.log(event.traceName)
  }
});

try {
  const scan = await client.scanIdentity("developer:dev_123");
  const graph = await client.getIdentityGraph(scan.subjectId);
  const request: PerformIdentityActionRequest = {
    subjectId: scan.subjectId,
    actionType: "LockIdentity"
  };
  const action = await client.performAction(request);

  console.log(graph.graphId, action.actionId);
} catch (error) {
  if (error instanceof AegirSecurityError) {
    console.error(error.status, error.code, error.correlationId);
  }
}
```

## Java / Maven

```java
import cloud.foxlin.aegir.security.AegirDiagnosticsHooks;
import cloud.foxlin.aegir.security.AegirSecurityClient;
import cloud.foxlin.aegir.security.AegirSecurityError;
import cloud.foxlin.aegir.security.PerformIdentityActionRequest;
import cloud.foxlin.aegir.security.SecurityModels;

import java.net.http.HttpClient;

public final class AegirQuickstart {
    public static void main(String[] args) throws Exception {
        AegirSecurityClient client = new AegirSecurityClient(
            "https://api.aegir.foxlinindustries.com/apis",
            System.getenv("AEGIR_DEVELOPER_KEY"),
            HttpClient.newHttpClient(),
            new AegirDiagnosticsHooks(
                entry -> System.out.println(entry.eventName()),
                event -> System.out.println(event.metricName()),
                trace -> System.out.println(trace.traceName())));

        try {
            SecurityModels.ScanIdentityResult scan = client.scanIdentity("developer:dev_123");
            SecurityModels.IdentityGraphSnapshot graph = client.getIdentityGraph(scan.getSubjectId());
            SecurityModels.IdentityActionRecord action = client.performAction(
                new PerformIdentityActionRequest(
                    scan.getSubjectId(),
                    SecurityModels.IdentityActionType.LockIdentity,
                    null,
                    null));

            System.out.println(graph.getGraphId() + " " + action.getActionId());
        } catch (AegirSecurityError ex) {
            System.out.println(ex.getStatus() + " " + ex.getErrorCode() + " " + ex.getCorrelationId());
        }
    }
}
```

## Python / PyPI

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
    config_key=None,
    developer_key=None,
    diagnostics_hooks=AegirDiagnosticsHooks(
        log=lambda entry: print(entry["eventName"]),
        metric=lambda event: print(event["metricName"]),
        trace=lambda event: print(event["traceName"]),
    ),
)

try:
    scan = client.scanIdentity("developer:dev_123")
    graph = client.getIdentityGraph(scan.subjectId)
    action = client.performAction(
        PerformIdentityActionRequest(scan.subjectId, IdentityActionType.LockIdentity)
    )
    print(graph.graphId, action.actionId)
except AegirSecurityError as ex:
    print(ex.status, ex.code, ex.correlationId)
```

## Go Module

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
		ConfigKey:    "",
		DeveloperKey: "",
		HTTPClient:   http.DefaultClient,
		Diagnostics: &aegirsecurity.DiagnosticsHooks{
			Log:    func(entry aegirsecurity.LogEntry) { fmt.Println(entry.EventName) },
			Metric: func(event aegirsecurity.MetricEvent) { fmt.Println(event.MetricName) },
			Trace:  func(event aegirsecurity.TraceEvent) { fmt.Println(event.TraceName) },
		},
	})

	scan, err := client.ScanIdentity("developer:dev_123")
	if err != nil {
		if typed, ok := err.(*aegirsecurity.AegirSecurityError); ok {
			fmt.Println(typed.Status, typed.Code, typed.CorrelationID)
		}
		return
	}

	graph, err := client.GetIdentityGraph(scan.SubjectID)
	if err != nil {
		fmt.Println(err)
		return
	}

	action, err := client.PerformAction(aegirsecurity.PerformIdentityActionRequest{
		SubjectID:  scan.SubjectID,
		ActionType: aegirsecurity.IdentityActionTypeLockIdentity,
	})
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(graph.GraphID, action.ActionID)
}
```
