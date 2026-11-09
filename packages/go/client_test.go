package aegirsecurity

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) Do(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestScanIdentity(t *testing.T) {
	client := newTrustedTestClient("https://example.test/apis", "", "", roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return jsonResponse(200, `{"subjectId":"developer:dev_123","graph":{"graphId":"graph:developer:dev_123","generatedAtUtc":"2026-04-07T15:00:00Z","scores":{"exposureScore":0.15,"trustScore":0.92,"connectionClarityScore":0.88},"nodes":[{"nodeId":"developer:dev_123","nodeType":"User","displayName":"dev_123@example.com","status":"active","trustTier":"high","observedAtUtc":"2026-04-07T15:00:00Z","lastVerifiedAtUtc":null,"metadata":{}}],"edges":[],"metadata":{}},"exposure":{"graphId":"graph:developer:dev_123","generatedAtUtc":"2026-04-07T15:00:00Z","exposureScore":0.15,"findings":[{"findingId":"finding_001","category":"WeakConnection","severity":"Medium","summary":"Weak service linkage.","nodeId":"developer:dev_123","edgeId":null,"metadata":{}}],"summaryText":"Low exposure posture."},"actionHistory":[{"actionId":"action_001","subjectId":"developer:dev_123","actionType":"VerifyConnection","status":"Completed","targetNodeId":"application:app_portal","reason":"Go sample validation.","requestedAtUtc":"2026-04-07T15:00:00Z","reversedAtUtc":null,"reverseReason":null,"metadata":{}}]}`), nil
	}))

	result, err := client.ScanIdentity("developer:dev_123")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if result.SubjectID != "developer:dev_123" {
		t.Fatalf("unexpected subject id %s", result.SubjectID)
	}
	if result.Graph.Nodes[0].NodeType != IdentityGraphNodeTypeUser {
		t.Fatalf("unexpected node type %s", result.Graph.Nodes[0].NodeType)
	}
	if result.Exposure.Findings[0].Category != ExposureFindingCategoryWeakConnection {
		t.Fatalf("unexpected finding category %s", result.Exposure.Findings[0].Category)
	}
	if result.Exposure.Findings[0].Severity != ExposureFindingSeverityMedium {
		t.Fatalf("unexpected finding severity %s", result.Exposure.Findings[0].Severity)
	}
	if result.ActionHistory[0].ActionType != IdentityActionTypeVerifyConnection {
		t.Fatalf("unexpected action type %s", result.ActionHistory[0].ActionType)
	}
	if result.ActionHistory[0].Status != IdentityActionStatusCompleted {
		t.Fatalf("unexpected action status %s", result.ActionHistory[0].Status)
	}
}

func TestHeadersAreAttached(t *testing.T) {
	client := newTrustedTestClient("https://example.test/apis", "config-key", "developer-key", roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("X-Aegir-Config-Key") != "" {
			t.Fatalf("configuration secret forwarded to identity route")
		}
		if req.Header.Get("X-Aegir-Developer-Key") != "developer-key" {
			t.Fatalf("missing developer header")
		}
		return jsonResponse(200, `{"graphId":"graph:developer:dev_123","generatedAtUtc":"2026-04-07T15:00:00Z","scores":{"exposureScore":0.15,"trustScore":0.92,"connectionClarityScore":0.88},"nodes":[],"edges":[],"metadata":{}}`), nil
	}))

	_, err := client.GetIdentityGraph("developer:dev_123")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestNonTwoHundredReturnsAegirSecurityError(t *testing.T) {
	client := newTrustedTestClient("https://example.test/apis", "", "", roundTripFunc(func(req *http.Request) (*http.Response, error) {
		response := jsonResponse(404, `{"error":"not_found"}`)
		response.Header.Set("X-Correlation-Id", "corr_123")
		return response, nil
	}))

	_, err := client.GetExposureSummary("developer:dev_123")
	if err == nil {
		t.Fatalf("expected error")
	}

	typedError, ok := err.(*AegirSecurityError)
	if !ok {
		t.Fatalf("expected AegirSecurityError, got %T", err)
	}
	if typedError.Code != AegirErrorCodeNotFound {
		t.Fatalf("expected not_found code, got %s", typedError.Code)
	}
	if typedError.CorrelationID != "corr_123" {
		t.Fatalf("expected corr_123 correlation id, got %s", typedError.CorrelationID)
	}
}

func TestDiagnosticsHooksReceiveEvents(t *testing.T) {
	logs := make([]AegirLogEntry, 0)
	metrics := make([]AegirMetricEvent, 0)
	traces := make([]AegirTraceEvent, 0)

	client := NewAegirSecurityClientWithOptions(ClientOptions{
		BaseURL:          "https://example.test/apis",
		TrustHTTPAdapter: true,
		HTTPClient: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			response := jsonResponse(200, `{"graphId":"graph:developer:dev_123","generatedAtUtc":"2026-04-07T15:00:00Z","scores":{"exposureScore":0.15,"trustScore":0.92,"connectionClarityScore":0.88},"nodes":[],"edges":[],"metadata":{}}`)
			response.Header.Set("X-Correlation-Id", "corr_diag")
			return response, nil
		}),
		Diagnostics: &DiagnosticsHooks{
			Log:    func(entry LogEntry) { logs = append(logs, entry) },
			Metric: func(event MetricEvent) { metrics = append(metrics, event) },
			Trace:  func(event TraceEvent) { traces = append(traces, event) },
		},
	})

	if _, err := client.GetIdentityGraph("developer:dev_123"); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if logs[0].EventName != "request.start" {
		t.Fatalf("expected request.start log, got %s", logs[0].EventName)
	}
	if metrics[0].MetricName != "aegir.client.request.duration" {
		t.Fatalf("unexpected metric %s", metrics[0].MetricName)
	}
	if traces[len(traces)-1].CorrelationID != "corr_diag" {
		t.Fatalf("expected corr_diag trace correlation id, got %s", traces[len(traces)-1].CorrelationID)
	}
}

func TestPublicModelsMarshalToBeta1WireShape(t *testing.T) {
	reason := "risk response"
	targetNodeID := "developer:dev_123"
	payload := ScanIdentityResult{
		SubjectID: "developer:dev_123",
		Graph: IdentityGraphSnapshot{
			GraphID:        "graph:developer:dev_123",
			GeneratedAtUTC: "2026-04-07T15:00:00Z",
			Scores: IdentityGraphScores{
				ExposureScore:          0.15,
				TrustScore:             0.92,
				ConnectionClarityScore: 0.88,
			},
			Nodes: []IdentityGraphNode{{
				NodeID:        "developer:dev_123",
				NodeType:      IdentityGraphNodeTypeDeveloper,
				DisplayName:   "Dev 123",
				Status:        "active",
				TrustTier:     "verified",
				ObservedAtUTC: "2026-04-07T14:59:00Z",
				Metadata:      map[string]*string{},
			}},
			Edges:    []IdentityGraphEdge{},
			Metadata: map[string]*string{},
		},
		Exposure: ExposureSummary{
			GraphID:        "graph:developer:dev_123",
			GeneratedAtUTC: "2026-04-07T15:00:00Z",
			ExposureScore:  0.15,
			Findings: []ExposureFinding{{
				FindingID: "finding:1",
				Category:  ExposureFindingCategoryWeakConnection,
				Severity:  ExposureFindingSeverityMedium,
				Summary:   "Weak service linkage.",
				NodeID:    &targetNodeID,
				Metadata:  map[string]*string{},
			}},
			SummaryText: "Low exposure posture.",
		},
		ActionHistory: []IdentityActionRecord{{
			ActionID:       "action:1",
			SubjectID:      "developer:dev_123",
			ActionType:     IdentityActionTypeVerifyConnection,
			Status:         IdentityActionStatusCompleted,
			TargetNodeID:   &targetNodeID,
			Reason:         &reason,
			RequestedAtUTC: "2026-04-07T15:01:00Z",
			Metadata:       map[string]*string{},
		}},
	}

	buffer, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("expected marshal to succeed, got %v", err)
	}
	text := string(buffer)
	for _, expected := range []string{
		`"nodeType":"Developer"`,
		`"category":"WeakConnection"`,
		`"severity":"Medium"`,
		`"actionType":"VerifyConnection"`,
		`"status":"Completed"`,
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("expected marshaled JSON to contain %s, got %s", expected, text)
		}
	}
}

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}
}

func newTrustedTestClient(base, config, developer string, adapter HTTPDoer) *AegirSecurityClient {
	return NewAegirSecurityClientWithOptions(ClientOptions{BaseURL: base, ConfigKey: config, DeveloperKey: developer, HTTPClient: adapter, TrustHTTPAdapter: true})
}
