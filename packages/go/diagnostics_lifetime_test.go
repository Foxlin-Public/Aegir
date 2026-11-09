// Copyright Foxlin Industries. Host diagnostics cannot extend authority lifetimes.
package aegirsecurity

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func diagnosticClient(hooks *DiagnosticsHooks, timeout time.Duration) *AegirSecurityClient {
	return NewAegirSecurityClientWithOptions(ClientOptions{BaseURL: "https://example.test", HTTPClient: roundTripFunc(func(*http.Request) (*http.Response, error) { return jsonResponse(200, legacyGraph), nil }), TrustHTTPAdapter: true, Timeout: timeout, Diagnostics: hooks})
}
func TestLegacyDiagnosticDeadlineCancelCloseAndNoLateResult(t *testing.T) {
	for _, phase := range []string{"request.start", "request.complete"} {
		for _, mode := range []string{"deadline", "cancel", "close"} {
			t.Run(phase+"-"+mode, func(t *testing.T) {
				entered := make(chan struct{}, 1)
				release := make(chan struct{})
				var once sync.Once
				defer once.Do(func() { close(release) })
				c := diagnosticClient(&DiagnosticsHooks{Log: func(e LogEntry) {
					if e.EventName == phase {
						entered <- struct{}{}
						<-release
					}
				}}, 150*time.Millisecond)
				defer c.Close()
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				type result struct {
					value *IdentityGraphSnapshot
					err   error
				}
				done := make(chan result, 1)
				go func() { v, e := c.GetIdentityGraphContext(ctx, "developer:dev_123"); done <- result{v, e} }()
				select {
				case <-entered:
				case <-time.After(time.Second):
					t.Fatal("hook not reached")
				}
				start := time.Now()
				if mode == "cancel" {
					cancel()
				}
				if mode == "close" {
					c.Close()
				}
				select {
				case r := <-done:
					if r.err == nil || r.value != nil || time.Since(start) > time.Second {
						t.Fatal("diagnostic returned/adopted late result")
					}
					if strings.Contains(r.err.Error(), "synthetic-private") {
						t.Fatal("hook data disclosed")
					}
				case <-time.After(time.Second):
					t.Fatal("hook defeated lifetime")
				}
				once.Do(func() { close(release) })
				waitDiagnosticIdle(t)
			})
		}
	}
}
func TestLegacyDiagnosticPanicSanitizedBestEffort(t *testing.T) {
	c := diagnosticClient(&DiagnosticsHooks{Log: func(LogEntry) { panic("synthetic-private-diagnostic") }, Metric: func(MetricEvent) { panic("synthetic-private-diagnostic") }, Trace: func(TraceEvent) { panic("synthetic-private-diagnostic") }}, time.Second)
	defer c.Close()
	if _, e := c.GetIdentityGraph("developer:dev_123"); e != nil {
		t.Fatal("optional diagnostic panic escaped")
	}
}
func TestLegacyDiagnosticGlobalResourceBudget(t *testing.T) {
	waitDiagnosticIdle(t)
	release := make(chan struct{})
	defer close(release)
	entered := make(chan struct{}, 4)
	var callbacks atomic.Int32
	clients := []*AegirSecurityClient{}
	done := make(chan error, 4)
	for i := 0; i < 4; i++ {
		c := diagnosticClient(&DiagnosticsHooks{Log: func(LogEntry) { callbacks.Add(1); entered <- struct{}{}; <-release }}, 100*time.Millisecond)
		clients = append(clients, c)
		go func() { _, e := c.GetIdentityGraph("developer:dev_123"); done <- e }()
	}
	defer func() {
		for _, c := range clients {
			c.Close()
		}
	}()
	for i := 0; i < 4; i++ {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("bounded hooks not entered")
		}
	}
	for i := 0; i < 4; i++ {
		select {
		case e := <-done:
			if e == nil {
				t.Fatal("hung callback allowed result")
			}
		case <-time.After(time.Second):
			t.Fatal("hung callback blocked caller")
		}
	}
	if len(legacyDiagnosticSlots) != 4 || callbacks.Load() != 4 {
		t.Fatal("unexpected callback budget")
	}
	var extra atomic.Int32
	c := diagnosticClient(&DiagnosticsHooks{Log: func(LogEntry) { extra.Add(1) }}, time.Second)
	defer c.Close()
	if _, e := c.GetIdentityGraph("developer:dev_123"); e != nil || extra.Load() != 0 {
		t.Fatal("saturated optional hooks queued/unbounded or changed authority")
	}
}

type nilMapRoundTripper map[string]int

func (nilMapRoundTripper) RoundTrip(*http.Request) (*http.Response, error) { panic("nil map invoked") }

type nilSliceRoundTripper []int

func (nilSliceRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	panic("nil slice invoked")
}

type nilChanRoundTripper chan int

func (nilChanRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	panic("nil channel invoked")
}
func TestLegacyAllNilCapableTrustedTransportsFailClosed(t *testing.T) {
	var m nilMapRoundTripper
	var s nilSliceRoundTripper
	var ch nilChanRoundTripper
	for _, transport := range []http.RoundTripper{m, s, ch} {
		c := NewAegirSecurityClientWithOptions(ClientOptions{BaseURL: "https://example.test", HTTPClient: &http.Client{Transport: transport}, TrustHTTPAdapter: true})
		if _, e := c.GetIdentityGraph("developer:dev_123"); e == nil {
			t.Fatal("typed-nil opaque transport accepted")
		}
		c.Close()
	}
}

func waitDiagnosticIdle(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for len(legacyDiagnosticSlots) > 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(legacyDiagnosticSlots) != 0 {
		t.Fatal("callback resources not released after host returned")
	}
}
