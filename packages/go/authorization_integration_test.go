// Copyright Foxlin Industries. Transport adversarial tests; real parity is separate.
package aegirsecurity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func integrationTestClient(t *testing.T, check func(http.ResponseWriter, *http.Request)) (*AuthorizationIntegration, *FileAuthorizationJournal) {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/authorization/events":
			fmt.Fprint(w, `{"deliveryId":null,"events":[],"requiresSnapshot":false,"reason":null,"retryAfterSeconds":0}`)
		case "/v1/authorization/snapshot":
			fmt.Fprint(w, `{"snapshotId":"snapshot-current","groups":[]}`)
		case "/v1/authorization/snapshot/ack":
			w.WriteHeader(204)
		case "/v1/authorization/check":
			check(w, r)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(server.Close)
	journal, e := NewFileAuthorizationJournal(filepath.Join(t.TempDir(), "journal.json"))
	if e != nil {
		t.Fatal(e)
	}
	pin := sha256.Sum256(server.Certificate().Raw)
	client, e := NewAuthorizationIntegration(IntegrationConfig{APIBaseURL: server.URL + "/", WebBaseURL: server.URL + "/", ApplicationCredential: strings.Repeat("x", 80), OrganizationID: "org-test", ApplicationID: "app-test", DevelopmentCertificateSHA256: hex.EncodeToString(pin[:]), Timeout: time.Second}, journal)
	if e != nil {
		journal.Close()
		t.Fatal(e)
	}
	t.Cleanup(func() { client.Close() })
	if e = client.Reconnect(context.Background()); e != nil {
		t.Fatal(e)
	}
	return client, journal
}
func validDecision() string {
	return `{"isAuthorized":true,"reason":"authorized","applicationSubjectId":"opaque-subject","authorizationEpoch":0,"effectiveGroupIds":["opaque-group"],"permissions":["read","write"]}`
}

func TestIntegrationCurrentPermitAndCommitRevalidation(t *testing.T) {
	var checks atomic.Int32
	client, _ := integrationTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		checks.Add(1)
		if r.Header.Get("X-Aegir-Application-Key") == "" {
			t.Error("missing credential")
		}
		fmt.Fprint(w, validDecision())
	})
	effects := 0
	d, e := client.ExecuteProtected(context.Background(), "ticket", "write", "opaque-subject", func(ctx context.Context) error {
		if _, e := client.BeforeCommit(ctx, "ticket", "write", "opaque-subject"); e != nil {
			return e
		}
		effects++
		return nil
	})
	if e != nil || !d.IsAuthorized || effects != 1 || checks.Load() != 2 {
		t.Fatalf("permit/revalidation failed decision=%v effects=%d checks=%d", d.IsAuthorized, effects, checks.Load())
	}
	if e = client.Poll(context.Background()); e != nil {
		t.Fatal(e)
	}
	if !client.Authorize(context.Background(), "ticket", "read", "").IsAuthorized {
		t.Fatal("healthy poll caused avoidable denial")
	}
}
func TestIntegrationMalformedAndContradictoryResponses(t *testing.T) {
	cases := map[string]struct {
		status int
		body   string
	}{
		"forbidden-permit":     {403, validDecision()},
		"success-denial":       {200, strings.Replace(validDecision(), `"isAuthorized":true`, `"isAuthorized":false`, 1)},
		"contradictory-reason": {200, strings.Replace(validDecision(), `"authorized"`, `"license_required"`, 1)},
		"missing-reason":       {200, strings.Replace(validDecision(), `"reason":"authorized",`, "", 1)},
		"null-epoch":           {200, strings.Replace(validDecision(), `"authorizationEpoch":0`, `"authorizationEpoch":null`, 1)},
		"null-alias":           {200, strings.Replace(validDecision(), `"opaque-subject"`, `null`, 1)},
		"wrong-permission":     {200, strings.Replace(validDecision(), `["read","write"]`, `["read"]`, 1)},
		"empty-groups":         {200, strings.Replace(validDecision(), `["opaque-group"]`, `[]`, 1)},
		"duplicate-property":   {200, strings.Replace(validDecision(), `"isAuthorized":true`, `"isAuthorized":false,"isAuthorized":true`, 1)},
		"invalid-json":         {200, `{"isAuthorized":true`},
		"trailing-json":        {200, validDecision() + `{}`},
		"wrong-casing":         {200, strings.Replace(validDecision(), `"isAuthorized"`, `"IsAuthorized"`, 1)},
	}
	for name, item := range cases {
		t.Run(name, func(t *testing.T) {
			client, _ := integrationTestClient(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(item.status); fmt.Fprint(w, item.body) })
			effects := 0
			d, e := client.ExecuteProtected(context.Background(), "ticket", "write", "", func(context.Context) error { effects++; return nil })
			if e != nil || d.IsAuthorized || effects != 0 {
				t.Fatal("malformed authority invoked effect")
			}
		})
	}
}
func TestIntegrationAliasScopeAndUnsupportedOperations(t *testing.T) {
	client, _ := integrationTestClient(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, validDecision()) })
	if client.Authorize(context.Background(), "ticket", "read", "foreign-subject").IsAuthorized {
		t.Fatal("subject substitution permitted")
	}
	if e := client.Reconnect(context.Background()); e != nil {
		t.Fatal(e)
	}
	if client.Authorize(context.Background(), "ticket", "delete", "").IsAuthorized {
		t.Fatal("unsupported scope permitted")
	}
}
func TestIntegrationRedirectDoesNotForwardCredential(t *testing.T) {
	var forwarded atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { forwarded.Add(1) }))
	defer target.Close()
	client, _ := integrationTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", target.URL)
		w.WriteHeader(307)
	})
	if client.Authorize(context.Background(), "ticket", "read", "").IsAuthorized || forwarded.Load() != 0 {
		t.Fatal("redirect followed")
	}
}

func TestIntegrationRejectsWrongResponseMediaType(t *testing.T) {
	client, _ := integrationTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/jsonp")
		fmt.Fprint(w, validDecision())
	})
	effects := 0
	decision, e := client.ExecuteProtected(context.Background(), "ticket", "write", "", func(context.Context) error { effects++; return nil })
	if e != nil || decision.IsAuthorized || effects != 0 {
		t.Fatal("wrong response media type permitted callback")
	}
}
func TestIntegrationCancellationAndClose(t *testing.T) {
	started := make(chan struct{}, 1)
	client, _ := integrationTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	})
	result := make(chan AuthorizationDecision, 1)
	go func() { result <- client.Authorize(context.Background(), "ticket", "read", "") }()
	<-started
	before := time.Now()
	if e := client.Close(); e != nil {
		t.Fatal(e)
	}
	select {
	case d := <-result:
		if d.IsAuthorized {
			t.Fatal("close granted access")
		}
	case <-time.After(time.Second):
		t.Fatal("request did not stop on close")
	}
	if time.Since(before) > time.Second {
		t.Fatal("close exceeded bounded cancellation")
	}
	if client.Authorize(context.Background(), "ticket", "read", "").IsAuthorized {
		t.Fatal("closed client granted")
	}
}
func TestIntegrationTransportConfigRejectsDowngradeAndForeignPin(t *testing.T) {
	for _, raw := range []string{"http://127.0.0.1/", "https://user:password@example.test/", "https://example.test/path?secret=x", "https://example.test"} {
		j, e := NewFileAuthorizationJournal(filepath.Join(t.TempDir(), "journal"))
		if e != nil {
			t.Fatal(e)
		}
		_, e = NewAuthorizationIntegration(IntegrationConfig{APIBaseURL: raw, WebBaseURL: raw, ApplicationCredential: "credential", OrganizationID: "org", ApplicationID: "app"}, j)
		j.Close()
		if e == nil {
			t.Fatalf("unsafe endpoint accepted %s", raw)
		}
	}
	j, _ := NewFileAuthorizationJournal(filepath.Join(t.TempDir(), "journal"))
	defer j.Close()
	_, e := NewAuthorizationIntegration(IntegrationConfig{APIBaseURL: "https://example.test/", WebBaseURL: "https://example.test/", ApplicationCredential: "credential", OrganizationID: "org", ApplicationID: "app", DevelopmentCertificateSHA256: strings.Repeat("0", 64)}, j)
	if e == nil {
		t.Fatal("development pin accepted outside loopback")
	}
}
func TestIntegrationTLSWrongPinDenied(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("wrong pin reached application") }))
	defer server.Close()
	j, journalError := NewFileAuthorizationJournal(filepath.Join(t.TempDir(), "journal"))
	if journalError != nil {
		t.Fatal(journalError)
	}
	client, e := NewAuthorizationIntegration(IntegrationConfig{APIBaseURL: server.URL + "/", WebBaseURL: server.URL + "/", ApplicationCredential: "credential", OrganizationID: "org", ApplicationID: "app", DevelopmentCertificateSHA256: strings.Repeat("0", 64), Timeout: time.Second}, j)
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	if e = client.Reconnect(context.Background()); e == nil {
		t.Fatal("wrong pin accepted")
	}
}

func TestIntegrationNilJournalAndCredentialRedaction(t *testing.T) {
	var journal *FileAuthorizationJournal
	cfg := IntegrationConfig{APIBaseURL: "https://example.test/", WebBaseURL: "https://example.test/", ApplicationCredential: "private-test-credential", OrganizationID: "org", ApplicationID: "app"}
	if _, e := NewAuthorizationIntegration(cfg, journal); e == nil {
		t.Fatal("typed nil journal accepted")
	}
	serialized, e := json.Marshal(cfg)
	if e != nil || strings.Contains(string(serialized), cfg.ApplicationCredential) {
		t.Fatal("configuration serialized credential")
	}
	if strings.Contains(fmt.Sprintf("%v %#v", cfg, cfg), cfg.ApplicationCredential) {
		t.Fatal("configuration formatter exposed credential")
	}
}

func notification(id, kind string, version int64) AuthorizationNotification {
	return AuthorizationNotification{ProtocolVersion: 1, TransactionID: "same-transaction", EventID: id, GroupID: "group-alias", EventType: kind, GroupVersion: version}
}
func TestIntegrationJournalAtomicDedupOrderingAndRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "journal.json")
	j, e := NewFileAuthorizationJournal(path)
	if e != nil {
		t.Fatal(e)
	}
	binding := strings.Repeat("a", 64)
	if e = j.Bind(ctx, binding); e != nil {
		t.Fatal(e)
	}
	events := []AuthorizationNotification{notification("event-1", "granted", 1), notification("event-2", "membershipChanged", 1), notification("event-3", "revoked", 2)}
	result, e := j.Apply(ctx, events)
	if e != nil || result.NewEffects != 3 {
		t.Fatal("different events sharing transaction lost")
	}
	result, e = j.Apply(ctx, events)
	if e != nil || result.NewEffects != 0 {
		t.Fatal("duplicate effects")
	}
	result, e = j.Apply(ctx, []AuthorizationNotification{notification("late-grant", "granted", 1)})
	if e != nil || result.NewEffects != 0 {
		t.Fatal("late grant effect")
	}
	result, e = j.Apply(ctx, []AuthorizationNotification{notification("would-apply", "revoked", 3), notification("future", "future-type", 4)})
	if e != nil || !result.RequiresSnapshot {
		t.Fatal("unknown event accepted")
	}
	stats, _ := j.Stats(ctx)
	if stats.Receipts != 4 || stats.Effects != 3 {
		t.Fatal("partial unknown batch committed")
	}
	if _, e = j.Apply(ctx, []AuthorizationNotification{notification("event-3", "granted", 2)}); e == nil {
		t.Fatal("contradictory duplicate accepted")
	}
	if e = j.ApplySnapshot(ctx, AuthorizationSnapshot{SnapshotID: "old", Groups: []AuthorizationSnapshotGroup{{GroupID: "group-alias", GroupVersion: 1, Subjects: []AuthorizationSnapshotSubject{}}}}); e == nil {
		t.Fatal("snapshot rollback accepted")
	}
	if e = j.Close(); e != nil {
		t.Fatal(e)
	}
	restarted, e := NewFileAuthorizationJournal(path)
	if e != nil {
		t.Fatal(e)
	}
	defer restarted.Close()
	if e = restarted.Bind(ctx, binding); e != nil {
		t.Fatal(e)
	}
	stats, _ = restarted.Stats(ctx)
	if stats.Connected || stats.Receipts != 4 || stats.Effects != 3 {
		t.Fatal("restart lost durable state")
	}
	if e = restarted.Bind(ctx, strings.Repeat("b", 64)); e == nil {
		t.Fatal("cross-application journal accepted")
	}
	result, e = restarted.Apply(ctx, events)
	if e != nil || result.NewEffects != 0 {
		t.Fatal("restart dedup failed")
	}
}
func TestIntegrationJournalLockCorruptionAndCanceledTransaction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal")
	j, e := NewFileAuthorizationJournal(path)
	if e != nil {
		t.Fatal(e)
	}
	if second, e := NewFileAuthorizationJournal(path); e == nil {
		second.Close()
		t.Fatal("second writer acquired lock")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = j.Apply(canceled, []AuthorizationNotification{notification("canceled", "revoked", 1)}); e == nil {
		t.Fatal("canceled transaction committed")
	}
	stats, _ := j.Stats(context.Background())
	if stats.Effects != 0 {
		t.Fatal("canceled effect")
	}
	j.Close()
	bytes, _ := os.ReadFile(path)
	var envelope map[string]any
	json.Unmarshal(bytes, &envelope)
	envelope["sha256"] = strings.Repeat("0", 64)
	bytes, _ = json.Marshal(envelope)
	os.WriteFile(path, bytes, 0600)
	if broken, e := NewFileAuthorizationJournal(path); e == nil {
		broken.Close()
		t.Fatal("corrupt journal accepted")
	}
}
