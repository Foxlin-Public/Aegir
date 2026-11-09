// Copyright Foxlin Industries. Synthetic loopback transport negatives; never an authority substitute.
package aegirsecurity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const legacyGraph = `{"graphId":"graph:developer:dev_123","generatedAtUtc":"2026-04-07T15:00:00Z","scores":{"exposureScore":0.15,"trustScore":0.92,"connectionClarityScore":0.88},"nodes":[],"edges":[],"metadata":{}}`

func legacyTLSFixture(t *testing.T, handler http.HandlerFunc, timeout time.Duration) *AegirSecurityClient {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	pin := sha256.Sum256(server.Certificate().Raw)
	c := NewAegirSecurityClientWithOptions(ClientOptions{BaseURL: server.URL, DeveloperKey: "synthetic-developer-key", ConfigKey: "synthetic-configuration-secret", CertificateSHA256: hex.EncodeToString(pin[:]), Timeout: timeout})
	t.Cleanup(func() { c.Close() })
	return c
}
func TestLegacyUnsafeConfigurationsDenyBeforeAdapter(t *testing.T) {
	for _, base := range []string{"http://127.0.0.1/", "https://user:secret@example.test/", "https://example.test/?token=x", "https://example.test/#fragment", "https://example.test/../path"} {
		t.Run(base[:4]+fmt.Sprint(len(base)), func(t *testing.T) {
			var calls atomic.Int32
			c := NewAegirSecurityClient(base, "", "", roundTripFunc(func(*http.Request) (*http.Response, error) { calls.Add(1); return jsonResponse(200, legacyGraph), nil }))
			defer c.Close()
			if _, e := c.GetIdentityGraph("developer:dev_123"); e == nil || calls.Load() != 0 {
				t.Fatal("unsafe origin/opaque adapter accepted")
			}
		})
	}
}
func TestLegacyOpaqueAdapterExplicitTrustAndConcreteClone(t *testing.T) {
	adapter := roundTripFunc(func(*http.Request) (*http.Response, error) { return jsonResponse(200, legacyGraph), nil })
	c := NewAegirSecurityClient("https://example.test", "", "", adapter)
	defer c.Close()
	if _, e := c.GetIdentityGraph("developer:dev_123"); e == nil {
		t.Fatal("unmarked opaque adapter accepted")
	}
	trusted := NewAegirSecurityClientWithOptions(ClientOptions{BaseURL: "https://example.test", HTTPClient: adapter, TrustHTTPAdapter: true})
	defer trusted.Close()
	if _, e := trusted.GetIdentityGraph("developer:dev_123"); e != nil {
		t.Fatal(e)
	}
	original := &http.Client{Timeout: time.Minute}
	cloned := NewAegirSecurityClientWithOptions(ClientOptions{BaseURL: "https://example.test", HTTPClient: original})
	defer cloned.Close()
	if original.Timeout != time.Minute || original.CheckRedirect != nil || cloned.httpClient == original {
		t.Fatal("caller client mutated/shared")
	}
}
func TestLegacyPinnedTLSAndConfigurationSecretOmitted(t *testing.T) {
	c := legacyTLSFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Aegir-Config-Key") != "" || r.Header.Get("X-Aegir-Developer-Key") != "synthetic-developer-key" {
			t.Error("credential boundary")
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		fmt.Fprint(w, legacyGraph)
	}, time.Second)
	if _, e := c.GetIdentityGraph("developer:dev_123"); e != nil {
		t.Fatal(e)
	}
}
func TestLegacyRedirectNeverTransmitsCredentials(t *testing.T) {
	var destination atomic.Int32
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { destination.Add(1) }))
	defer other.Close()
	c := legacyTLSFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", other.URL)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(307)
		fmt.Fprint(w, legacyGraph)
	}, time.Second)
	if _, e := c.GetIdentityGraph("developer:dev_123"); e == nil || destination.Load() != 0 {
		t.Fatal("redirect followed")
	}
}
func TestLegacyStrictWireAndBinding(t *testing.T) {
	cases := map[string]struct {
		body, mime string
		status     int
	}{"duplicate": {strings.Replace(legacyGraph, `"graphId":`, `"graphId":"wrong","graphId":`, 1), "application/json", 200}, "casevariant": {strings.Replace(legacyGraph, `"graphId":`, `"GraphId":"wrong","graphId":`, 1), "application/json", 200}, "missing": {strings.Replace(legacyGraph, `"edges":[],`, "", 1), "application/json", 200}, "wrongcase": {strings.Replace(legacyGraph, `"graphId"`, `"GraphId"`, 1), "application/json", 200}, "foreign": {strings.Replace(legacyGraph, "graph:developer:dev_123", "graph:developer:other", 1), "application/json", 200}, "trailing": {legacyGraph + `{}`, "application/json", 200}, "malformed": {`{"graphId":true,}`, "application/json", 200}, "oversized": {`{"x":"` + strings.Repeat("a", authorizationMaxBody) + `"}`, "application/json", 200}, "deep": {strings.Repeat("[", 34) + `0` + strings.Repeat("]", 34), "application/json", 200}, "unpaired-surrogate": {`{"x":"\ud800"}`, "application/json", 200},
		"wrongcharset": {legacyGraph, "application/json; charset=iso-8859-1", 200},
		"wrongmime":    {legacyGraph, "application/jsonp", 200}, "empty": {"", "application/json", 200}, "unexpectedstatus": {legacyGraph, "application/json", 201}, "wrongtype": {strings.Replace(legacyGraph, `"exposureScore":0.15`, `"exposureScore":"0.15"`, 1), "application/json", 200}, "invalidutf8": {string([]byte{'{', '"', 'x', '"', ':', '"', 255, '"', '}'}), "application/json", 200}}
	for name, item := range cases {
		t.Run(name, func(t *testing.T) {
			c := legacyTLSFixture(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", item.mime)
				w.WriteHeader(item.status)
				fmt.Fprint(w, item.body)
			}, time.Second)
			if _, e := c.GetIdentityGraph("developer:dev_123"); e == nil {
				t.Fatal("invalid response accepted")
			}
		})
	}
}
func TestLegacyDefaultTrustRejectsUntrustedTLSAndWrongPin(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, legacyGraph)
	}))
	defer server.Close()
	for _, pin := range []string{"", strings.Repeat("0", 64)} {
		c := NewAegirSecurityClientWithOptions(ClientOptions{BaseURL: server.URL, CertificateSHA256: pin, Timeout: time.Second})
		if _, e := c.GetIdentityGraph("developer:dev_123"); e == nil {
			t.Fatal("untrusted TLS accepted")
		}
		c.Close()
	}
}
func TestLegacySanitizedErrorsDiagnosticsAndOptions(t *testing.T) {
	var logs []LogEntry
	var traces []TraceEvent
	adapter := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		resp := jsonResponse(403, `{"error":"synthetic-secret-upstream","message":"synthetic-developer-key"}`)
		resp.Header.Set("X-Correlation-Id", strings.Repeat("x", 129))
		return resp, nil
	})
	c := NewAegirSecurityClientWithOptions(ClientOptions{BaseURL: "https://example.test", DeveloperKey: "synthetic-developer-key", HTTPClient: adapter, TrustHTTPAdapter: true, Diagnostics: &DiagnosticsHooks{Log: func(e LogEntry) { logs = append(logs, e) }, Trace: func(e TraceEvent) { traces = append(traces, e) }}})
	defer c.Close()
	_, e := c.ReverseAction("private-action", strPtr("private-reason"))
	typed, ok := e.(*AegirSecurityError)
	if !ok || typed.Body != "" || typed.CorrelationID != "" || typed.Code != AegirErrorCodeForbidden {
		t.Fatal("raw response exposed")
	}
	encoded, _ := json.Marshal([]any{logs, traces})
	if strings.Contains(string(encoded), "private-action") || strings.Contains(string(encoded), "private-reason") || strings.Contains(string(encoded), "synthetic-secret") {
		t.Fatal("diagnostic disclosure")
	}
	options := ClientOptions{BaseURL: "https://user:secret@example.test", ConfigKey: "configuration-secret", DeveloperKey: "developer-secret"}
	encoded, _ = json.Marshal(options)
	for _, s := range []string{fmt.Sprintf("%v", options), fmt.Sprintf("%#v", options), string(encoded), fmt.Sprintf("%#v", c)} {
		if strings.Contains(s, "developer-secret") || strings.Contains(s, "configuration-secret") || strings.Contains(s, "synthetic-developer-key") {
			t.Fatal("formatted credential disclosure")
		}
	}
}
func strPtr(s string) *string { return &s }
func TestLegacyDeadlineContextAndClose(t *testing.T) {
	for _, mode := range []string{"deadline", "context", "close"} {
		t.Run(mode, func(t *testing.T) {
			entered := make(chan struct{}, 1)
			c := legacyTLSFixture(t, func(w http.ResponseWriter, r *http.Request) { entered <- struct{}{}; <-r.Context().Done() }, 120*time.Millisecond)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			start := time.Now()
			go func() { _, e := c.GetIdentityGraphContext(ctx, "developer:dev_123"); done <- e }()
			select {
			case <-entered:
			case <-time.After(2 * time.Second):
				t.Fatal("request not received")
			}
			if mode == "context" {
				cancel()
			}
			if mode == "close" {
				c.Close()
			}
			select {
			case e := <-done:
				if e == nil || time.Since(start) > time.Second {
					t.Fatal("unbounded cancellation")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("request leaked")
			}
			if mode == "close" {
				if _, e := c.GetIdentityGraph("developer:dev_123"); e == nil {
					t.Fatal("closed client reused")
				}
			}
		})
	}
}
func TestLegacyCollectionBound(t *testing.T) {
	large := []any{}
	for i := 0; i < 10001; i++ {
		large = append(large, map[string]any{})
	}
	if legacyShape(large, reflectTypeActions(), 0) {
		t.Fatal("collection bound ignored")
	}
}
func reflectTypeActions() reflect.Type { return reflect.TypeOf([]IdentityActionRecord{}) }

var _ io.Reader

type nilLegacyAdapter struct{}

func (*nilLegacyAdapter) Do(*http.Request) (*http.Response, error) {
	panic("typed nil must never be invoked")
}
func TestLegacyTypedNilAdaptersAndAdditiveResponse(t *testing.T) {
	var standard *http.Client
	var opaque *nilLegacyAdapter
	for _, adapter := range []HTTPDoer{standard, opaque} {
		c := NewAegirSecurityClientWithOptions(ClientOptions{BaseURL: "https://example.test", HTTPClient: adapter, TrustHTTPAdapter: true})
		if _, e := c.GetIdentityGraph("developer:dev_123"); e == nil {
			t.Fatal("typed nil accepted")
		}
		c.Close()
	}
	c := newTrustedTestClient("https://example.test", "", "", roundTripFunc(func(*http.Request) (*http.Response, error) {
		return jsonResponse(200, strings.Replace(legacyGraph, `"metadata":{}`, `"metadata":{},"optionalExtension":{"summary":"additional"}`, 1)), nil
	}))
	defer c.Close()
	if _, e := c.GetIdentityGraph("developer:dev_123"); e != nil {
		t.Fatal("bounded optional extension rejected", e)
	}
}
func TestLegacySecretComponentCorrelationRedacted(t *testing.T) {
	key := "dev_key_id:synthetic-private-component"
	c := newTrustedTestClient("https://example.test", "", key, roundTripFunc(func(*http.Request) (*http.Response, error) {
		r := jsonResponse(403, `{"error":"forbidden"}`)
		r.Header.Set("X-Correlation-Id", "corr-synthetic-private-component")
		return r, nil
	}))
	defer c.Close()
	_, e := c.GetIdentityGraph("developer:dev_123")
	typed, ok := e.(*AegirSecurityError)
	if !ok || typed.CorrelationID != "" {
		t.Fatal("credential component leaked")
	}
}

func TestLegacyEnumsMatchExactMember(t *testing.T) {
	if legacyShape("User|Device", reflect.TypeOf(IdentityGraphNodeTypeUser), 0) || legacyShape("Owns|Issued", reflect.TypeOf(IdentityGraphEdgeTypeOwns), 0) {
		t.Fatal("combined enum accepted")
	}
}

func TestLegacyCanonicalNumericEnumsNormalizeAndWrite(t *testing.T) {
	scanBody := `{"subjectId":"developer:dev_123","graph":{"graphId":"graph:developer:dev_123","generatedAtUtc":"2026-04-07T15:00:00Z","scores":{"exposureScore":0.15,"trustScore":0.92,"connectionClarityScore":0.88},"nodes":[{"nodeId":"developer:dev_123","nodeType":6,"displayName":"dev_123@example.com","status":"active","trustTier":"high","observedAtUtc":"2026-04-07T15:00:00Z","lastVerifiedAtUtc":null,"metadata":{}}],"edges":[{"edgeId":"edge:one","edgeType":1,"fromNodeId":"developer:dev_123","toNodeId":"app:one","status":"active","trustWeight":0.5,"evidenceType":"registration","reason":"synthetic","observedAtUtc":"2026-04-07T15:00:00Z","lastVerifiedAtUtc":null,"metadata":{}}],"metadata":{}},"exposure":{"graphId":"graph:developer:dev_123","generatedAtUtc":"2026-04-07T15:00:00Z","exposureScore":0.15,"findings":[{"findingId":"finding_001","category":1,"severity":2,"summary":"Weak service linkage.","nodeId":"developer:dev_123","edgeId":null,"metadata":{}}],"summaryText":"Low exposure posture."},"actionHistory":[{"actionId":"action_001","subjectId":"developer:dev_123","actionType":3,"status":1,"targetNodeId":"application:app_portal","reason":"Go sample validation.","requestedAtUtc":"2026-04-07T15:00:00Z","reversedAtUtc":null,"reverseReason":null,"metadata":{}}]}`
	c := legacyTLSFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, scanBody)
	}, time.Second)
	scan, e := c.ScanIdentity("developer:dev_123")
	if e != nil || scan.Graph.Nodes[0].NodeType != IdentityGraphNodeTypeUser || scan.Graph.Edges[0].EdgeType != IdentityGraphEdgeTypeOwns || scan.Exposure.Findings[0].Severity != ExposureFindingSeverityMedium || scan.ActionHistory[0].ActionType != IdentityActionTypeVerifyConnection {
		t.Fatal("canonical numeric response not normalized", e)
	}
	action := scan.ActionHistory[0]
	wire, _ := json.Marshal(action)
	var response map[string]any
	json.Unmarshal(wire, &response)
	response["actionType"] = 3
	response["status"] = 1
	wire, _ = json.Marshal(response)
	writer := legacyTLSFixture(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var payload map[string]any
		json.Unmarshal(body, &payload)
		if payload["actionType"] != float64(3) {
			t.Error("outgoing canonical numeric enum absent")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(wire)
	}, time.Second)
	if _, e := writer.PerformAction(PerformIdentityActionRequest{SubjectID: action.SubjectID, ActionType: IdentityActionTypeVerifyConnection, TargetNodeID: action.TargetNodeID}); e != nil {
		t.Fatal(e)
	}
}
func TestLegacyNumericEnumKnownExactIntegerOnly(t *testing.T) {
	types := []reflect.Type{reflect.TypeOf(IdentityActionTypeLockIdentity), reflect.TypeOf(IdentityActionStatusCompleted), reflect.TypeOf(IdentityGraphNodeTypeUser), reflect.TypeOf(IdentityGraphEdgeTypeOwns), reflect.TypeOf(ExposureFindingCategoryWeakConnection), reflect.TypeOf(ExposureFindingSeverityLow)}
	for _, typ := range types {
		if _, ok := legacyNormalizeEnums(json.Number("1"), typ); !ok {
			t.Fatal("known numeric enum rejected")
		}
		for _, invalid := range []any{json.Number("0"), json.Number("999"), json.Number("1.0"), json.Number("1e0"), "1", "Unknown", true, nil} {
			if _, ok := legacyNormalizeEnums(invalid, typ); ok {
				t.Fatal("invalid numeric enum accepted", typ.Name())
			}
		}
	}
}
func TestLegacyNestedTypedNilTransportDeny(t *testing.T) {
	var tr *http.Transport
	for _, trust := range []bool{false, true} {
		c := NewAegirSecurityClientWithOptions(ClientOptions{BaseURL: "https://example.test", HTTPClient: &http.Client{Transport: tr}, TrustHTTPAdapter: trust})
		if _, e := c.GetIdentityGraph("developer:dev_123"); e == nil {
			t.Fatal("nested typed nil transport accepted")
		}
		c.Close()
	}
}

func TestLegacyRawSubjectIDGraphAndExposureBinding(t *testing.T) {
	for _, kind := range []string{"developer", "user"} {
		t.Run(kind, func(t *testing.T) {
			subject := "raw-" + kind + "-id"
			graphID := "graph:" + kind + ":" + subject
			nodeType := 2
			if kind == "user" {
				nodeType = 6
			}
			node := map[string]any{"nodeId": kind + ":" + subject, "nodeType": nodeType, "displayName": "Synthetic identity", "status": "active", "trustTier": "verified", "observedAtUtc": "2026-04-07T15:00:00Z", "lastVerifiedAtUtc": nil, "metadata": map[string]any{}}
			var graph map[string]any
			json.Unmarshal([]byte(legacyGraph), &graph)
			graph["graphId"] = graphID
			graph["nodes"] = []any{node}
			exposure := map[string]any{"graphId": graphID, "generatedAtUtc": "2026-04-07T15:00:00Z", "exposureScore": 0.1, "findings": []any{}, "summaryText": "Synthetic"}
			var foreign atomic.Bool
			c := legacyTLSFixture(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				response := graph
				if strings.Contains(r.URL.Path, "/exposure/") {
					response = exposure
				}
				copy := map[string]any{}
				for k, v := range response {
					copy[k] = v
				}
				if foreign.Load() {
					copy["graphId"] = "graph:" + kind + ":unrelated-id"
				}
				json.NewEncoder(w).Encode(copy)
			}, time.Second)
			if _, e := c.GetIdentityGraph(subject); e != nil {
				t.Fatal("raw graph ID rejected", e)
			}
			if _, e := c.GetExposureSummary(subject); e != nil {
				t.Fatal("raw exposure ID rejected", e)
			}
			foreign.Store(true)
			if _, e := c.GetIdentityGraph(subject); e == nil {
				t.Fatal("foreign raw graph ID accepted")
			}
			if _, e := c.GetExposureSummary(subject); e == nil {
				t.Fatal("foreign raw exposure ID accepted")
			}
		})
	}
}
