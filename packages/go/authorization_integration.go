// Copyright Foxlin Industries. Unreleased RC1 developer integration.
package aegirsecurity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const authorizationMaxBody = 1 << 20

// IntegrationConfig contains secrets. Do not log or marshal configurations.
// Base addresses include an optional path prefix and must end with a slash.
type IntegrationConfig struct {
	APIBaseURL            string `json:"apiBaseUrl"`
	WebBaseURL            string `json:"webBaseUrl"`
	ApplicationCredential string `json:"applicationCredential"`
	OrganizationID        string `json:"organizationId"`
	ApplicationID         string `json:"applicationId"`
	// DevelopmentCertificateSHA256 enables only exact-certificate HTTPS loopback pinning.
	// It never changes machine trust and cannot be used for a non-loopback address.
	DevelopmentCertificateSHA256 string        `json:"certificateSha256"`
	Timeout                      time.Duration `json:"-"`
}

func (IntegrationConfig) String() string   { return "AegirIntegrationConfig(<redacted>)" }
func (IntegrationConfig) GoString() string { return "AegirIntegrationConfig(<redacted>)" }
func (c IntegrationConfig) MarshalJSON() ([]byte, error) {
	type wire IntegrationConfig
	safe := wire(c)
	safe.ApplicationCredential = "<redacted>"
	return json.Marshal(safe)
}

type AuthorizationNotification struct {
	ProtocolVersion int     `json:"protocolVersion"`
	TransactionID   string  `json:"transactionId"`
	EventID         string  `json:"eventId"`
	GroupID         string  `json:"groupId"`
	UserID          *string `json:"userId"`
	EventType       string  `json:"eventType"`
	GroupVersion    int64   `json:"groupVersion"`
}

type AuthorizationBatch struct {
	DeliveryID        *string                     `json:"deliveryId"`
	Events            []AuthorizationNotification `json:"events"`
	RequiresSnapshot  bool                        `json:"requiresSnapshot"`
	Reason            *string                     `json:"reason"`
	RetryAfterSeconds int                         `json:"retryAfterSeconds"`
}

type AuthorizationSnapshotSubject struct {
	UserID             string `json:"userId"`
	Allowed            bool   `json:"allowed"`
	AuthorizationEpoch int64  `json:"authorizationEpoch"`
}
type AuthorizationSnapshotGroup struct {
	GroupID      string                         `json:"groupId"`
	GroupVersion int64                          `json:"groupVersion"`
	Subjects     []AuthorizationSnapshotSubject `json:"subjects"`
}
type AuthorizationSnapshot struct {
	SnapshotID string                       `json:"snapshotId"`
	Groups     []AuthorizationSnapshotGroup `json:"groups"`
}
type AuthorizationDecision struct {
	IsAuthorized         bool     `json:"isAuthorized"`
	Reason               string   `json:"reason"`
	ApplicationSubjectID *string  `json:"applicationSubjectId"`
	AuthorizationEpoch   int64    `json:"authorizationEpoch"`
	EffectiveGroupIDs    []string `json:"effectiveGroupIds"`
	Permissions          []string `json:"permissions"`
}

// FreshAuthenticationResult never serializes the sensitive access ticket.
// MFARequired requires a second genuine password/MFA exchange using ChallengeID.
type FreshAuthenticationResult struct {
	AccessToken        string    `json:"-"`
	ChallengeID        string    `json:"-"`
	MFARequired        bool      `json:"mfaRequired"`
	ExpiresAtUTC       time.Time `json:"expiresAtUtc"`
	OrganizationID     string    `json:"organizationId"`
	ApplicationID      string    `json:"applicationId"`
	SubjectID          string    `json:"-"`
	AuthorizationEpoch int64     `json:"authorizationEpoch"`
}

func (FreshAuthenticationResult) String() string   { return "AegirFreshAuthentication(<redacted>)" }
func (FreshAuthenticationResult) GoString() string { return "AegirFreshAuthentication(<redacted>)" }

type AuthorizationApplyResult struct {
	NewEffects       int  `json:"newEffects"`
	RequiresSnapshot bool `json:"requiresSnapshot"`
}
type AuthorizationJournalStats struct {
	Receipts  int  `json:"receipts"`
	Effects   int  `json:"effects"`
	Connected bool `json:"connected"`
}

// AuthorizationJournal atomically commits receipts, monotonic versions and
// demonstrated invalidation effects. Hosts may implement this in their own DB.
// Events and snapshots never grant permission; every operation needs a server check.
type AuthorizationJournal interface {
	Bind(context.Context, string) error
	Apply(context.Context, []AuthorizationNotification) (AuthorizationApplyResult, error)
	ApplySnapshot(context.Context, AuthorizationSnapshot) error
	SetConnected(context.Context, bool) error
	Stats(context.Context) (AuthorizationJournalStats, error)
	Close() error
}

// AuthorizationIntegration owns its transport. It starts disconnected, has no
// background goroutines and must reconcile after startup or any network failure.
type AuthorizationIntegration struct {
	mu        sync.Mutex
	life      sync.Mutex
	config    IntegrationConfig
	http      *http.Client
	transport *http.Transport
	journal   AuthorizationJournal
	connected bool
	closed    bool
	lifetime  context.Context
	cancel    context.CancelFunc
}

func integrationBase(raw string) (*url.URL, error) {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !strings.HasSuffix(u.Path, "/") || u.Opaque != "" || strings.Contains(u.RawPath, "%") {
		return nil, errors.New("clean HTTPS base address ending with slash required")
	}
	return u, nil
}

// NewAuthorizationIntegration uses normal TLS verification by default, rejects
// redirects, sends no cookies, and never permits an HTTP transport downgrade.
func NewAuthorizationIntegration(config IntegrationConfig, journal AuthorizationJournal) (*AuthorizationIntegration, error) {
	api, e := integrationBase(config.APIBaseURL)
	if e != nil {
		return nil, e
	}
	web, e := integrationBase(config.WebBaseURL)
	if e != nil {
		return nil, e
	}
	if journal == nil || (reflect.ValueOf(journal).Kind() == reflect.Ptr && reflect.ValueOf(journal).IsNil()) || !integrationBound(config.ApplicationCredential, 512) || !integrationBound(config.OrganizationID, 128) || !integrationBound(config.ApplicationID, 128) {
		return nil, errors.New("bounded application credential, organization, application and durable journal required")
	}
	if config.Timeout == 0 {
		config.Timeout = 15 * time.Second
	}
	if config.Timeout < time.Millisecond || config.Timeout > 30*time.Second {
		return nil, errors.New("timeout must be positive and at most 30 seconds")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if config.DevelopmentCertificateSHA256 != "" {
		pin, er := hex.DecodeString(config.DevelopmentCertificateSHA256)
		allowed := func(u *url.URL) bool { h := u.Hostname(); return h == "localhost" || h == "127.0.0.1" || h == "::1" }
		if er != nil || len(pin) != 32 || !allowed(api) || !allowed(web) {
			return nil, errors.New("development certificate pin requires exact SHA256 and HTTPS loopback endpoints")
		}
		// Explicit certificate pin replaces CA trust only within this loopback client.
		tlsConfig.InsecureSkipVerify = true
		tlsConfig.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("development TLS certificate missing")
			}
			got := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if subtle.ConstantTimeCompare(pin, got[:]) != 1 {
				return errors.New("development TLS certificate pin mismatch")
			}
			return nil
		}
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: tlsConfig, MaxConnsPerHost: 4, MaxIdleConns: 4, IdleConnTimeout: 30 * time.Second, TLSHandshakeTimeout: config.Timeout, DialContext: (&net.Dialer{Timeout: config.Timeout}).DialContext}
	lifetime, cancel := context.WithCancel(context.Background())
	c := &AuthorizationIntegration{config: config, http: &http.Client{Transport: transport, Timeout: config.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, transport: transport, journal: journal, lifetime: lifetime, cancel: cancel}
	binding := sha256.Sum256([]byte(config.APIBaseURL + "\n" + config.OrganizationID + "\n" + config.ApplicationID))
	if e = journal.Bind(context.Background(), hex.EncodeToString(binding[:])); e == nil {
		e = journal.SetConnected(context.Background(), false)
	}
	if e != nil {
		cancel()
		transport.CloseIdleConnections()
		return nil, e
	}
	return c, nil
}

func integrationBound(v string, max int) bool {
	return strings.TrimSpace(v) != "" && len(v) <= max && !strings.ContainsAny(v, "\r\n\x00")
}
func integrationDenied(reason string) AuthorizationDecision {
	return AuthorizationDecision{Reason: reason, EffectiveGroupIDs: []string{}, Permissions: []string{}}
}

func (c *AuthorizationIntegration) request(ctx context.Context, web bool, method, path string, body any) (int, []byte, error) {
	c.life.Lock()
	if c.closed {
		c.life.Unlock()
		return 0, nil, errors.New("integration closed")
	}
	c.life.Unlock()
	reqCtx, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()
	stop := context.AfterFunc(c.lifetime, cancel)
	defer stop()
	var payload io.Reader
	if body != nil {
		b, e := json.Marshal(body)
		if e != nil {
			return 0, nil, errors.New("invalid request")
		}
		payload = bytes.NewReader(b)
	}
	base := c.config.APIBaseURL
	if web {
		base = c.config.WebBaseURL
	}
	req, e := http.NewRequestWithContext(reqCtx, method, base+path, payload)
	if e != nil {
		return 0, nil, errors.New("invalid request")
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if !web {
		req.Header.Set("X-Aegir-Application-Key", c.config.ApplicationCredential)
	}
	response, e := c.http.Do(req)
	if e != nil {
		return 0, nil, errors.New("authoritative transport unavailable")
	}
	defer response.Body.Close()
	data, e := io.ReadAll(io.LimitReader(response.Body, authorizationMaxBody+1))
	if e != nil || len(data) > authorizationMaxBody {
		return 0, nil, errors.New("invalid or oversized authority response")
	}
	if len(data) > 0 {
		mediaType, _, mediaError := mime.ParseMediaType(response.Header.Get("Content-Type"))
		if mediaError != nil || mediaType != "application/json" {
			return 0, nil, errors.New("authority response must be JSON")
		}
	}
	return response.StatusCode, data, nil
}

// AuthenticateFresh calls the actual Web password/MFA endpoint. Existing bearer
// tokens cannot substitute for this ceremony. Tokens remain the caller's secret.
func (c *AuthorizationIntegration) AuthenticateFresh(ctx context.Context, username, password, challengeID, totpCode string) (FreshAuthenticationResult, error) {
	if !integrationBound(username, 320) || !integrationBound(password, 2048) {
		return FreshAuthenticationResult{}, errors.New("bounded credentials required")
	}
	body := map[string]any{"username": username, "password": password, "organizationId": c.config.OrganizationID, "applicationId": c.config.ApplicationID, "challengeId": nil, "totpCode": nil}
	if challengeID != "" {
		body["challengeId"] = challengeID
	}
	if totpCode != "" {
		body["totpCode"] = totpCode
	}
	status, data, e := c.request(ctx, true, http.MethodPost, "account/organization-access", body)
	if e != nil {
		return FreshAuthenticationResult{}, e
	}
	obj, e := integrationObject(data)
	if e != nil {
		return FreshAuthenticationResult{}, e
	}
	if status == 400 && obj["error"] == "mfa_required" {
		id, ok := obj["challengeId"].(string)
		if !ok || !integrationBound(id, 512) {
			return FreshAuthenticationResult{}, errors.New("invalid MFA challenge")
		}
		return FreshAuthenticationResult{MFARequired: true, ChallengeID: id}, nil
	}
	if status != 200 {
		return FreshAuthenticationResult{}, errors.New("fresh authentication denied")
	}
	var wire struct {
		AccessToken        string    `json:"accessToken"`
		ExpiresAtUTC       time.Time `json:"expiresAtUtc"`
		OrganizationID     string    `json:"organizationId"`
		ApplicationID      string    `json:"applicationId"`
		SubjectID          string    `json:"subjectId"`
		AuthorizationEpoch int64     `json:"authorizationEpoch"`
	}
	if !integrationHas(obj, "accessToken", "expiresAtUtc", "organizationId", "applicationId", "subjectId", "authorizationEpoch") || json.Unmarshal(data, &wire) != nil || !integrationBound(wire.AccessToken, 512) || wire.OrganizationID != c.config.OrganizationID || wire.ApplicationID != c.config.ApplicationID || !integrationBound(wire.SubjectID, 128) || wire.AuthorizationEpoch < 0 || !wire.ExpiresAtUTC.After(time.Now()) {
		return FreshAuthenticationResult{}, errors.New("invalid fresh authentication response")
	}
	return FreshAuthenticationResult{AccessToken: wire.AccessToken, ExpiresAtUTC: wire.ExpiresAtUTC, OrganizationID: wire.OrganizationID, ApplicationID: wire.ApplicationID, SubjectID: wire.SubjectID, AuthorizationEpoch: wire.AuthorizationEpoch}, nil
}

func (c *AuthorizationIntegration) markDisconnected() {
	c.connected = false
	_ = c.journal.SetConnected(context.Background(), false)
}
func (c *AuthorizationIntegration) reconcileSnapshot(ctx context.Context) error {
	status, data, e := c.request(ctx, false, http.MethodGet, "v1/authorization/snapshot", nil)
	if e != nil {
		return e
	}
	if status != 200 {
		return errors.New("snapshot denied")
	}
	obj, e := integrationObject(data)
	if e != nil || !validAuthorizationSnapshotObject(obj) {
		return errors.New("invalid snapshot")
	}
	var snapshot AuthorizationSnapshot
	if json.Unmarshal(data, &snapshot) != nil {
		return errors.New("invalid snapshot")
	}
	if e = c.journal.ApplySnapshot(ctx, snapshot); e != nil {
		return e
	}
	status, _, e = c.request(ctx, false, http.MethodPost, "v1/authorization/snapshot/ack", map[string]string{"snapshotId": snapshot.SnapshotID})
	if e != nil {
		return e
	}
	if status != 204 {
		return errors.New("snapshot acknowledgment denied")
	}
	return nil
}

// Reconnect immediately reconciles an authorized snapshot and drains replay.
// It never trusts a persisted connected flag after restarting this process.
func (c *AuthorizationIntegration) Reconnect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.markDisconnected()
	if e := c.drain(ctx, true); e != nil {
		return e
	}
	c.markDisconnected()
	if e := c.reconcileSnapshot(ctx); e != nil {
		return e
	}
	return c.drain(ctx, true)
}

// Poll preserves healthy connected state during a routine empty polling cycle.
// It clears that state on any error, gap, reconciliation requirement or timeout.
func (c *AuthorizationIntegration) Poll(ctx context.Context) error {
	return c.PollWithAcknowledgment(ctx, true)
}

// PollWithAcknowledgment(false) demonstrates an applied batch whose ACK is lost.
// It leaves the consumer disconnected until Reconnect replays and acknowledges.
func (c *AuthorizationIntegration) PollWithAcknowledgment(ctx context.Context, acknowledge bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.connected {
		return errors.New("event reconciliation required")
	}
	return c.drain(ctx, acknowledge)
}

func (c *AuthorizationIntegration) drain(ctx context.Context, acknowledge bool) (err error) {
	defer func() {
		if err != nil {
			c.markDisconnected()
		}
	}()
	for attempt := 0; attempt < 20; attempt++ {
		status, data, e := c.request(ctx, false, http.MethodGet, "v1/authorization/events?limit=100", nil)
		if e != nil {
			return e
		}
		if status != 200 {
			return errors.New("event poll denied")
		}
		obj, e := integrationObject(data)
		if e != nil || !validAuthorizationBatchObject(obj) {
			return errors.New("invalid event batch")
		}
		var batch AuthorizationBatch
		if json.Unmarshal(data, &batch) != nil || batch.Events == nil || len(batch.Events) > 100 || batch.RetryAfterSeconds < 0 || batch.RetryAfterSeconds > 30 {
			return errors.New("invalid event batch")
		}
		if batch.RequiresSnapshot {
			c.markDisconnected()
			if e = c.reconcileSnapshot(ctx); e != nil {
				return e
			}
			continue
		}
		if batch.Reason != nil && *batch.Reason == "retry_backoff" {
			delay := batch.RetryAfterSeconds
			if delay < 1 {
				delay = 1
			}
			timer := time.NewTimer(time.Duration(delay) * time.Second)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-c.lifetime.Done():
				timer.Stop()
				return errors.New("integration closed")
			}
			continue
		}
		if len(batch.Events) == 0 {
			if e = c.journal.SetConnected(ctx, true); e != nil {
				return e
			}
			c.connected = true
			return nil
		}
		if batch.DeliveryID == nil || !integrationBound(*batch.DeliveryID, 512) {
			return errors.New("events require a delivery identity")
		}
		applied, e := c.journal.Apply(ctx, batch.Events)
		if e != nil {
			return e
		}
		if applied.RequiresSnapshot {
			c.markDisconnected()
			if e = c.reconcileSnapshot(ctx); e != nil {
				return e
			}
			continue
		}
		if !acknowledge {
			c.markDisconnected()
			return nil
		}
		status, _, e = c.request(ctx, false, http.MethodPost, "v1/authorization/ack", map[string]string{"deliveryId": *batch.DeliveryID})
		if e != nil {
			return e
		}
		if status != 204 {
			return errors.New("event acknowledgment denied")
		}
	}
	return errors.New("bounded replay attempts exceeded")
}

// Authorize performs a fresh current server check. expectedSubjectAlias may be
// empty when no prior binding is known; a permit always requires an opaque
// nonempty server alias, current epoch, groups and the exact read/write permission.
// This method never uses event payloads or snapshots as an authorization permit.
func (c *AuthorizationIntegration) Authorize(ctx context.Context, ticket, operation, expectedSubjectAlias string) AuthorizationDecision {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ctx.Err() != nil {
		return integrationDenied("operation_canceled")
	}
	if operation != "read" && operation != "write" {
		return integrationDenied("unsupported_operation")
	}
	if !integrationBound(ticket, 512) {
		return integrationDenied("fresh_authentication_required")
	}
	if !c.connected {
		return integrationDenied("event_reconciliation_required")
	}
	status, data, e := c.request(ctx, false, http.MethodPost, "v1/authorization/check", map[string]string{"accessToken": ticket, "operation": operation})
	if e != nil {
		c.markDisconnected()
		return integrationDenied("authoritative_access_unavailable")
	}
	obj, e := integrationObject(data)
	if e != nil || !integrationHas(obj, "isAuthorized", "reason", "applicationSubjectId", "authorizationEpoch", "effectiveGroupIds", "permissions") || !integrationInteger(obj["authorizationEpoch"], 0) {
		c.markDisconnected()
		return integrationDenied("invalid_authority_response")
	}
	var d AuthorizationDecision
	if json.Unmarshal(data, &d) != nil || !integrationBound(d.Reason, 256) || d.AuthorizationEpoch < 0 || d.EffectiveGroupIDs == nil || d.Permissions == nil || len(d.EffectiveGroupIDs) > 100 || len(d.Permissions) > 2 || (status != 200 && status != 403) || (d.IsAuthorized && status != 200) || (!d.IsAuthorized && (status != 403 || d.Reason == "authorized")) {
		c.markDisconnected()
		return integrationDenied("invalid_authority_response")
	}
	seenGroups := map[string]bool{}
	for _, g := range d.EffectiveGroupIDs {
		if !integrationBound(g, 512) || seenGroups[g] {
			c.markDisconnected()
			return integrationDenied("invalid_authority_response")
		}
		seenGroups[g] = true
	}
	seenPermissions := map[string]bool{}
	for _, p := range d.Permissions {
		if (p != "read" && p != "write") || seenPermissions[p] {
			c.markDisconnected()
			return integrationDenied("invalid_authority_response")
		}
		seenPermissions[p] = true
	}
	if d.IsAuthorized {
		hasPermission := false
		for _, p := range d.Permissions {
			if p == operation {
				hasPermission = true
			}
		}
		if d.Reason != "authorized" || d.ApplicationSubjectID == nil || !integrationBound(*d.ApplicationSubjectID, 512) || len(d.EffectiveGroupIDs) == 0 || !hasPermission || (expectedSubjectAlias != "" && expectedSubjectAlias != *d.ApplicationSubjectID) {
			c.markDisconnected()
			return integrationDenied("invalid_authority_response")
		}
	} else if d.Reason == "event_reconciliation_required" {
		c.markDisconnected()
	}
	return d
}

// ExecuteProtected calls effect only after a fresh permit. effect must still use
// BeforeCommit before committing its own independent database transaction.
func (c *AuthorizationIntegration) ExecuteProtected(ctx context.Context, ticket, operation, subjectAlias string, effect func(context.Context) error) (AuthorizationDecision, error) {
	if effect == nil {
		return integrationDenied("invalid_effect"), errors.New("protected callback required")
	}
	d := c.Authorize(ctx, ticket, operation, subjectAlias)
	if !d.IsAuthorized {
		return d, nil
	}
	if e := ctx.Err(); e != nil {
		return integrationDenied("operation_canceled"), e
	}
	return d, effect(ctx)
}

// BeforeCommit revalidates immediately before the application's commit. Aegir's
// check linearizes at its server transaction; a later independent DB commit is
// NOT atomically fenced against a subsequent revocation.
func (c *AuthorizationIntegration) BeforeCommit(ctx context.Context, ticket, operation, subjectAlias string) (AuthorizationDecision, error) {
	d := c.Authorize(ctx, ticket, operation, subjectAlias)
	if !d.IsAuthorized {
		return d, errors.New("protected commit denied")
	}
	return d, nil
}
func (c *AuthorizationIntegration) Disconnect() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.markDisconnected()
}

// Close cancels active network work, joins serialized consumer work, disposes
// the owned transport and closes the journal. No consumer goroutine is started.
func (c *AuthorizationIntegration) Close() error {
	c.life.Lock()
	if c.closed {
		c.life.Unlock()
		return nil
	}
	c.closed = true
	c.cancel()
	c.life.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.markDisconnected()
	c.transport.CloseIdleConnections()
	return c.journal.Close()
}

func integrationHas(m map[string]any, names ...string) bool {
	for _, n := range names {
		if _, ok := m[n]; !ok {
			return false
		}
	}
	return true
}
func integrationInteger(v any, min int64) bool {
	n, ok := v.(json.Number)
	if !ok {
		return false
	}
	value, e := strconv.ParseInt(n.String(), 10, 64)
	return e == nil && value >= min
}
func validAuthorizationBatchObject(m map[string]any) bool {
	if !integrationHas(m, "deliveryId", "events", "requiresSnapshot", "reason", "retryAfterSeconds") || !integrationInteger(m["retryAfterSeconds"], 0) {
		return false
	}
	if _, ok := m["requiresSnapshot"].(bool); !ok {
		return false
	}
	for _, name := range []string{"deliveryId", "reason"} {
		if m[name] != nil {
			if _, ok := m[name].(string); !ok {
				return false
			}
		}
	}
	events, ok := m["events"].([]any)
	if !ok || len(events) > 100 {
		return false
	}
	for _, raw := range events {
		event, ok := raw.(map[string]any)
		if !ok || len(event) != 7 || !integrationHas(event, "protocolVersion", "transactionId", "eventId", "groupId", "userId", "eventType", "groupVersion") || !integrationInteger(event["protocolVersion"], 1) || !integrationInteger(event["groupVersion"], 1) {
			return false
		}
		for _, name := range []string{"transactionId", "eventId", "groupId", "eventType"} {
			value, ok := event[name].(string)
			if !ok || !integrationBound(value, 512) {
				return false
			}
		}
		if event["userId"] != nil {
			value, ok := event["userId"].(string)
			if !ok || !integrationBound(value, 512) {
				return false
			}
		}
	}
	return true
}

func validAuthorizationSnapshotObject(m map[string]any) bool {
	if !integrationHas(m, "snapshotId", "groups") {
		return false
	}
	id, ok := m["snapshotId"].(string)
	if !ok || !integrationBound(id, 512) {
		return false
	}
	groups, ok := m["groups"].([]any)
	if !ok || len(groups) > 100 {
		return false
	}
	count := 0
	for _, raw := range groups {
		group, ok := raw.(map[string]any)
		if !ok || !integrationHas(group, "groupId", "groupVersion", "subjects") || !integrationInteger(group["groupVersion"], 0) {
			return false
		}
		id, ok := group["groupId"].(string)
		if !ok || !integrationBound(id, 512) {
			return false
		}
		subjects, ok := group["subjects"].([]any)
		if !ok {
			return false
		}
		for _, rawSubject := range subjects {
			count++
			subject, ok := rawSubject.(map[string]any)
			if !ok || count > 2000 || !integrationHas(subject, "userId", "allowed", "authorizationEpoch") || !integrationInteger(subject["authorizationEpoch"], 0) {
				return false
			}
			id, ok := subject["userId"].(string)
			if !ok || !integrationBound(id, 512) {
				return false
			}
			if _, ok := subject["allowed"].(bool); !ok {
				return false
			}
		}
	}
	return true
}

// Strict JSON rejects duplicate property names, trailing documents and excessive
// nesting, rather than letting contradictory fields become a false permit.
func integrationObject(data []byte) (map[string]any, error) {
	if !integrationUnicodeJSON(data) {
		return nil, errors.New("invalid JSON Unicode")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	value, e := integrationJSONValue(decoder, 0)
	if e != nil {
		return nil, errors.New("invalid authority JSON")
	}
	if _, e = decoder.Token(); e != io.EOF {
		return nil, errors.New("trailing authority JSON")
	}
	obj, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("authority JSON object required")
	}
	return obj, nil
}
func integrationJSONValue(d *json.Decoder, depth int) (any, error) {
	if depth > 32 {
		return nil, errors.New("JSON nesting limit")
	}
	token, e := d.Token()
	if e != nil {
		return nil, e
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return token, nil
	}
	if delim == '{' {
		m := map[string]any{}
		names := map[string]bool{}
		for d.More() {
			key, e := d.Token()
			if e != nil {
				return nil, e
			}
			name, ok := key.(string)
			if !ok {
				return nil, errors.New("JSON key required")
			}
			if names[strings.ToLower(name)] || len(m) >= 100000 {
				return nil, errors.New("duplicate JSON key")
			}
			v, e := integrationJSONValue(d, depth+1)
			if e != nil {
				return nil, e
			}
			names[strings.ToLower(name)] = true
			m[name] = v
		}
		end, e := d.Token()
		if e != nil || end != json.Delim('}') {
			return nil, errors.New("JSON closing object required")
		}
		return m, nil
	}
	if delim == '[' {
		a := []any{}
		for d.More() {
			if len(a) >= 100000 {
				return nil, errors.New("JSON array bound")
			}
			v, e := integrationJSONValue(d, depth+1)
			if e != nil {
				return nil, e
			}
			a = append(a, v)
		}
		end, e := d.Token()
		if e != nil || end != json.Delim(']') {
			return nil, errors.New("JSON closing array required")
		}
		return a, nil
	}
	return nil, fmt.Errorf("invalid JSON delimiter")
}

// Reject ill-formed Unicode rather than silently replacing an escaped surrogate.
func integrationUnicodeJSON(data []byte) bool {
	if !utf8.Valid(data) {
		return false
	}
	quoted := false
	for i := 0; i < len(data); i++ {
		switch data[i] {
		case '"':
			quoted = !quoted
		case '\\':
			if !quoted {
				continue
			}
			i++
			if i >= len(data) {
				return false
			}
			if data[i] != 'u' {
				continue
			}
			if i+4 >= len(data) {
				return false
			}
			code, e := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
			if e != nil {
				return false
			}
			i += 4
			if code >= 0xD800 && code <= 0xDBFF {
				if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
					return false
				}
				low, e := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
				if e != nil || low < 0xDC00 || low > 0xDFFF {
					return false
				}
				i += 6
			} else if code >= 0xDC00 && code <= 0xDFFF {
				return false
			}
		}
	}
	return true
}
