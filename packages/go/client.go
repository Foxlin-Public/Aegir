// Copyright Foxlin Industries. HTTPS-only retained security client.
package aegirsecurity

import (
	"bytes"
	"context"
	"crypto/sha256"
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
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}
type AegirSecurityClient struct {
	baseURL, developerKey string
	httpClient            HTTPDoer
	transport             *http.Transport
	diagnostics           *DiagnosticsHooks
	timeout               time.Duration
	lifetime              context.Context
	cancel                context.CancelFunc
	initErr               error
	closed                atomic.Bool
}
type ClientOptions struct {
	BaseURL      string
	ConfigKey    string            `json:"-"`
	DeveloperKey string            `json:"-"`
	HTTPClient   HTTPDoer          `json:"-"`
	Diagnostics  *DiagnosticsHooks `json:"-"`
	Timeout      time.Duration
	// TrustHTTPAdapter explicitly admits opaque host code, which can bypass wire security.
	// It is never needed for a concrete standard-library client and never implies certification.
	TrustHTTPAdapter bool
	// Exact DER SHA256, accepted only for literal HTTPS loopback development endpoints.
	CertificateSHA256 string `json:"-"`
}

func (o ClientOptions) String() string   { return "AegirClientOptions(<redacted>)" }
func (o ClientOptions) GoString() string { return o.String() }
func (o ClientOptions) MarshalJSON() ([]byte, error) {
	return []byte(`{"credentials":"redacted"}`), nil
}
func (c *AegirSecurityClient) String() string   { return "AegirSecurityClient(<redacted>)" }
func (c *AegirSecurityClient) GoString() string { return c.String() }

type LogEntry struct {
	Level         string            `json:"level"`
	EventName     string            `json:"eventName"`
	Message       string            `json:"message"`
	Operation     string            `json:"operation"`
	CorrelationID string            `json:"correlationId"`
	OccurredAtUTC string            `json:"occurredAtUtc"`
	Metadata      map[string]string `json:"metadata"`
}

type MetricEvent struct {
	MetricName    string            `json:"metricName"`
	Value         float64           `json:"value"`
	Unit          string            `json:"unit"`
	ObservedAtUTC string            `json:"observedAtUtc"`
	Dimensions    map[string]string `json:"dimensions"`
}

type TraceEvent struct {
	TraceName     string            `json:"traceName"`
	Operation     string            `json:"operation"`
	TracePhase    string            `json:"tracePhase"`
	OccurredAtUTC string            `json:"occurredAtUtc"`
	CorrelationID string            `json:"correlationId"`
	Metadata      map[string]string `json:"metadata"`
}

type AegirLogEntry = LogEntry
type AegirMetricEvent = MetricEvent
type AegirTraceEvent = TraceEvent

type DiagnosticsHooks struct {
	Log    func(LogEntry)
	Metric func(MetricEvent)
	Trace  func(TraceEvent)
}

func NewAegirSecurityClient(baseURL, configKey, developerKey string, client HTTPDoer) *AegirSecurityClient {
	return NewAegirSecurityClientWithOptions(ClientOptions{BaseURL: baseURL, ConfigKey: configKey, DeveloperKey: developerKey, HTTPClient: client})
}
func NewAegirSecurityClientWithOptions(o ClientOptions) *AegirSecurityClient {
	lifetime, cancel := context.WithCancel(context.Background())
	c := &AegirSecurityClient{developerKey: o.DeveloperKey, diagnostics: o.Diagnostics, lifetime: lifetime, cancel: cancel, timeout: o.Timeout}
	if c.timeout == 0 {
		c.timeout = 15 * time.Second
	}
	if c.timeout < time.Millisecond || c.timeout > 30*time.Second {
		c.initErr = errors.New("bounded timeout required")
	}
	u, e := url.Parse(o.BaseURL)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || strings.Contains(u.RawPath, "%") || strings.Contains(u.Path, "..") || !legacyInput(o.DeveloperKey, 2048, true) {
		c.initErr = errors.New("clean HTTPS origin and valid credential required")
	} else {
		c.baseURL = strings.TrimRight(u.String(), "/")
	}
	if legacyNilAdapter(o.HTTPClient) {
		c.initErr = errors.New("nil HTTP adapter")
		return c
	}
	var supplied *http.Client
	if o.HTTPClient == nil {
		supplied = &http.Client{}
	} else if concrete, ok := o.HTTPClient.(*http.Client); ok {
		supplied = concrete
	} else if o.TrustHTTPAdapter && o.CertificateSHA256 == "" {
		c.httpClient = o.HTTPClient
	} else {
		c.initErr = errors.New("opaque HTTP adapter requires explicit host trust")
	}
	if supplied != nil {
		clone := *supplied
		clone.Jar = nil
		clone.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		clone.Timeout = c.timeout
		var tr *http.Transport
		if legacyNilAdapter(supplied.Transport) {
			c.initErr = errors.New("nil transport")
			return c
		}

		if supplied.Transport == nil {
			tr = &http.Transport{}
		} else if concrete, ok := supplied.Transport.(*http.Transport); ok {
			if concrete == nil {
				c.initErr = errors.New("nil transport")
				return c
			}
			tr = &http.Transport{TLSClientConfig: concrete.TLSClientConfig}
		} else if o.TrustHTTPAdapter && o.CertificateSHA256 == "" {
			clone.Transport = supplied.Transport
		} else {
			c.initErr = errors.New("opaque transport requires explicit host trust")
		}
		if tr != nil {
			tr.Proxy = nil
			tc := &tls.Config{MinVersion: tls.VersionTLS12}
			if tr.TLSClientConfig != nil {
				existing := tr.TLSClientConfig
				if existing.InsecureSkipVerify || existing.VerifyConnection != nil || existing.VerifyPeerCertificate != nil || existing.GetClientCertificate != nil || len(existing.Certificates) > 0 {
					c.initErr = errors.New("unverifiable TLS configuration")
				}
				tc.RootCAs = existing.RootCAs
				tc.ServerName = ""
			}
			if o.CertificateSHA256 != "" {
				pin, err := hex.DecodeString(o.CertificateSHA256)
				host := ""
				if u != nil {
					host = u.Hostname()
				}
				if err != nil || len(pin) != 32 || (host != "localhost" && host != "127.0.0.1" && host != "::1") {
					c.initErr = errors.New("exact loopback certificate pin required")
				} else {
					tc.InsecureSkipVerify = true
					tc.VerifyConnection = func(cs tls.ConnectionState) error {
						if len(cs.PeerCertificates) == 0 {
							return errors.New("certificate missing")
						}
						cert := cs.PeerCertificates[0]
						if time.Now().Before(cert.NotBefore) || time.Now().After(cert.NotAfter) || cert.VerifyHostname(host) != nil {
							return errors.New("certificate host mismatch")
						}
						sum := sha256.Sum256(cert.Raw)
						if !bytes.Equal(pin, sum[:]) {
							return errors.New("certificate pin mismatch")
						}
						return nil
					}
				}
			}
			tr.TLSClientConfig = tc
			tr.TLSHandshakeTimeout = c.timeout
			tr.ResponseHeaderTimeout = c.timeout
			tr.DialTLS = nil
			tr.DialTLSContext = nil
			tr.DialContext = (&net.Dialer{Timeout: c.timeout}).DialContext
			clone.Transport = tr
			c.transport = tr
		}
		c.httpClient = &clone
	}
	return c
}

// Close cancels in-flight standard transport calls and releases owned idle connections.
func (c *AegirSecurityClient) Close() error {
	if !c.closed.Swap(true) {
		if c.cancel != nil {
			c.cancel()
		}
		if c.transport != nil {
			c.transport.CloseIdleConnections()
		}
	}
	return nil
}
func (c *AegirSecurityClient) ScanIdentity(subjectID string) (*ScanIdentityResult, error) {
	return c.ScanIdentityContext(context.Background(), subjectID)
}
func (c *AegirSecurityClient) GetIdentityGraph(subjectID string) (*IdentityGraphSnapshot, error) {
	return c.GetIdentityGraphContext(context.Background(), subjectID)
}
func (c *AegirSecurityClient) GetIdentityGraphJSON(subjectID string) (string, error) {
	return c.GetIdentityGraphJSONContext(context.Background(), subjectID)
}
func (c *AegirSecurityClient) GetExposureSummary(subjectID string) (*ExposureSummary, error) {
	return c.GetExposureSummaryContext(context.Background(), subjectID)
}
func (c *AegirSecurityClient) PerformAction(action PerformIdentityActionRequest) (*IdentityActionRecord, error) {
	return c.PerformActionContext(context.Background(), action)
}
func (c *AegirSecurityClient) ReverseAction(actionID string, reason *string) (*IdentityActionRecord, error) {
	return c.ReverseActionContext(context.Background(), actionID, reason)
}
func (c *AegirSecurityClient) GetActionHistory(subjectID string) ([]IdentityActionRecord, error) {
	return c.GetActionHistoryContext(context.Background(), subjectID)
}
func (c *AegirSecurityClient) ScanIdentityContext(ctx context.Context, subjectID string) (*ScanIdentityResult, error) {
	if !legacyInput(subjectID, 512, false) {
		return nil, legacyError(0, AegirErrorCodeInvalidRequest)
	}
	var payload ScanIdentityResult
	if err := c.request(ctx, "scanIdentity", "/security/scan/"+url.PathEscape(subjectID), http.MethodGet, nil, &payload); err != nil {
		return nil, err
	}
	if !(payload.SubjectID == subjectID && legacyGraphBinding(payload.Graph.GraphID, subjectID) && legacyGraphBinding(payload.Exposure.GraphID, subjectID) && legacyHistoryBinding(payload.ActionHistory, subjectID)) {
		return nil, legacyError(0, AegirErrorCodeInvalidRequest)
	}
	return &payload, nil
}

func (c *AegirSecurityClient) GetIdentityGraphContext(ctx context.Context, subjectID string) (*IdentityGraphSnapshot, error) {
	if !legacyInput(subjectID, 512, false) {
		return nil, legacyError(0, AegirErrorCodeInvalidRequest)
	}
	var payload IdentityGraphSnapshot
	if err := c.request(ctx, "getIdentityGraph", "/security/graphs/"+url.PathEscape(subjectID), http.MethodGet, nil, &payload); err != nil {
		return nil, err
	}
	if !(legacyGraphBinding(payload.GraphID, subjectID)) {
		return nil, legacyError(0, AegirErrorCodeInvalidRequest)
	}
	return &payload, nil
}

func (c *AegirSecurityClient) GetIdentityGraphJSONContext(ctx context.Context, subjectID string) (string, error) {
	payload, err := c.GetIdentityGraphContext(ctx, subjectID)
	if err != nil {
		return "", err
	}

	buffer, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	return string(buffer), nil
}

func (c *AegirSecurityClient) GetExposureSummaryContext(ctx context.Context, subjectID string) (*ExposureSummary, error) {
	if !legacyInput(subjectID, 512, false) {
		return nil, legacyError(0, AegirErrorCodeInvalidRequest)
	}
	var payload ExposureSummary
	if err := c.request(ctx, "getExposureSummary", "/security/exposure/"+url.PathEscape(subjectID), http.MethodGet, nil, &payload); err != nil {
		return nil, err
	}
	if !(legacyGraphBinding(payload.GraphID, subjectID)) {
		return nil, legacyError(0, AegirErrorCodeInvalidRequest)
	}
	return &payload, nil
}

func (c *AegirSecurityClient) PerformActionContext(ctx context.Context, action PerformIdentityActionRequest) (*IdentityActionRecord, error) {
	if !legacyInput(action.SubjectID, 512, false) || !legacyShape(string(action.ActionType), reflect.TypeOf(action.ActionType), 0) {
		return nil, legacyError(0, AegirErrorCodeInvalidRequest)
	}
	var payload IdentityActionRecord
	if err := c.request(ctx, "performAction", "/security/actions", http.MethodPost, action, &payload); err != nil {
		return nil, err
	}
	if !(payload.SubjectID == action.SubjectID && payload.ActionType == action.ActionType && payload.Status == IdentityActionStatusCompleted && legacySameString(payload.TargetNodeID, action.TargetNodeID)) {
		return nil, legacyError(0, AegirErrorCodeInvalidRequest)
	}
	return &payload, nil
}

func (c *AegirSecurityClient) ReverseActionContext(ctx context.Context, actionID string, reason *string) (*IdentityActionRecord, error) {
	if !legacyInput(actionID, 512, false) {
		return nil, legacyError(0, AegirErrorCodeInvalidRequest)
	}
	suffix := ""
	if reason != nil {
		suffix = "?reason=" + url.QueryEscape(*reason)
	}

	var payload IdentityActionRecord
	if err := c.request(ctx, "reverseAction", "/security/actions/"+url.PathEscape(actionID)+"/reverse"+suffix, http.MethodPost, nil, &payload); err != nil {
		return nil, err
	}
	if !(payload.ActionID == actionID && payload.Status == IdentityActionStatusReversed) {
		return nil, legacyError(0, AegirErrorCodeInvalidRequest)
	}
	return &payload, nil
}

func (c *AegirSecurityClient) GetActionHistoryContext(ctx context.Context, subjectID string) ([]IdentityActionRecord, error) {
	if !legacyInput(subjectID, 512, false) {
		return nil, legacyError(0, AegirErrorCodeInvalidRequest)
	}
	var payload []IdentityActionRecord
	if err := c.request(ctx, "getActionHistory", "/security/actions/history/"+url.PathEscape(subjectID), http.MethodGet, nil, &payload); err != nil {
		return nil, err
	}
	if !legacyHistoryBinding(payload, subjectID) {
		return nil, legacyError(0, AegirErrorCodeInvalidRequest)
	}
	return payload, nil
}

func legacyError(status int, code AegirErrorCode) *AegirSecurityError {
	return &AegirSecurityError{Status: status, Code: code}
}
func legacyInput(s string, max int, empty bool) bool {
	return (empty || strings.TrimSpace(s) != "") && len(s) <= max && !strings.ContainsAny(s, "\r\n\x00")
}
func (c *AegirSecurityClient) request(ctx context.Context, operation, path, method string, body any, target any) error {
	if c.initErr != nil || c.httpClient == nil || c.closed.Load() || ctx == nil {
		return legacyError(0, AegirErrorCodeInvalidRequest)
	}
	reqCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	stop := context.AfterFunc(c.lifetime, cancel)
	defer stop()
	var reader io.Reader
	if body != nil {
		if action, ok := body.(PerformIdentityActionRequest); ok {
			names := legacyEnumNames("IdentityActionType")
			number := 0
			for i, name := range names {
				if name == string(action.ActionType) {
					number = i + 1
				}
			}
			if number == 0 {
				return legacyError(0, AegirErrorCodeInvalidRequest)
			}
			wire := map[string]any{"subjectId": action.SubjectID, "actionType": number}
			if action.TargetNodeID != nil {
				wire["targetNodeId"] = *action.TargetNodeID
			}
			if action.Reason != nil {
				wire["reason"] = *action.Reason
			}
			body = wire
		}
		b, e := json.Marshal(body)
		if e != nil || len(b) > authorizationMaxBody {
			return legacyError(0, AegirErrorCodeInvalidRequest)
		}
		reader = bytes.NewReader(b)
	}
	if !legacyInput(path, 8192, false) {
		return legacyError(0, AegirErrorCodeInvalidRequest)
	}
	req, e := http.NewRequestWithContext(reqCtx, method, c.baseURL+"/v1"+path, reader)
	if e != nil {
		return legacyError(0, AegirErrorCodeInvalidRequest)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.developerKey != "" {
		req.Header.Set("X-Aegir-Developer-Key", c.developerKey)
	}
	start := time.Now()
	if !c.emitTrace(reqCtx, TraceEvent{TraceName: "request.start", Operation: operation, TracePhase: "request.start", OccurredAtUTC: start.UTC().Format(time.RFC3339), Metadata: map[string]string{"method": method}}) {
		return legacyError(0, AegirErrorCodeTransportError)
	}
	if !c.emitLog(reqCtx, LogEntry{Level: "information", EventName: "request.start", Message: "Starting " + operation + ".", Operation: operation, OccurredAtUTC: start.UTC().Format(time.RFC3339), Metadata: map[string]string{"method": method}}) {
		return legacyError(0, AegirErrorCodeTransportError)
	}
	resp, e := c.httpClient.Do(req)
	if e != nil {
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		return legacyError(0, AegirErrorCodeTransportError)
	}
	if resp == nil || resp.Body == nil {
		return legacyError(0, AegirErrorCodeTransportError)
	}
	defer resp.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(resp.Body, authorizationMaxBody+1))
	if e != nil || len(raw) > authorizationMaxBody || !utf8.Valid(raw) {
		return legacyError(resp.StatusCode, AegirErrorCodeInvalidRequest)
	}
	ct, params, e := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if e != nil || ct != "application/json" || len(resp.Header.Values("Content-Type")) != 1 || params["charset"] != "" && !strings.EqualFold(params["charset"], "utf-8") {
		return legacyError(resp.StatusCode, AegirErrorCodeInvalidRequest)
	}
	value, e := legacyJSON(raw)
	if e != nil {
		return legacyError(resp.StatusCode, AegirErrorCodeInvalidRequest)
	}
	code := resolveErrorCode(resp.StatusCode, raw)
	correlation := resp.Header.Get("X-Correlation-Id")
	if !legacyCorrelation(correlation, c.developerKey) {
		correlation = ""
	}
	if !c.emitMetric(reqCtx, MetricEvent{MetricName: "aegir.client.request.duration", Value: float64(time.Since(start).Microseconds()) / 1000, Unit: "ms", ObservedAtUTC: time.Now().UTC().Format(time.RFC3339), Dimensions: map[string]string{"operation": operation, "status": fmt.Sprint(resp.StatusCode), "errorCode": string(code)}}) {
		return legacyError(0, AegirErrorCodeTransportError)
	}
	if resp.StatusCode != http.StatusOK {
		if !c.emitTrace(reqCtx, TraceEvent{TraceName: "request.error", Operation: operation, TracePhase: "request.error", CorrelationID: correlation, OccurredAtUTC: time.Now().UTC().Format(time.RFC3339), Metadata: map[string]string{"errorCode": string(code)}}) {
			return legacyError(0, AegirErrorCodeTransportError)
		}
		return &AegirSecurityError{Status: resp.StatusCode, Code: code, CorrelationID: correlation}
	}
	if target == nil {
		return legacyError(resp.StatusCode, AegirErrorCodeInvalidRequest)
	}
	value, valid := legacyNormalizeEnums(value, reflect.TypeOf(target).Elem())
	if !valid || !legacyShape(value, reflect.TypeOf(target).Elem(), 0) {
		return legacyError(resp.StatusCode, AegirErrorCodeInvalidRequest)
	}
	normalized, marshalErr := json.Marshal(value)
	if marshalErr != nil || json.Unmarshal(normalized, target) != nil {
		return legacyError(resp.StatusCode, AegirErrorCodeInvalidRequest)
	}
	if !c.emitLog(reqCtx, LogEntry{Level: "information", EventName: "request.complete", Message: "Completed " + operation + ".", Operation: operation, CorrelationID: correlation, OccurredAtUTC: time.Now().UTC().Format(time.RFC3339)}) {
		return legacyError(0, AegirErrorCodeTransportError)
	}
	if !c.emitTrace(reqCtx, TraceEvent{TraceName: "request.complete", Operation: operation, TracePhase: "request.complete", CorrelationID: correlation, OccurredAtUTC: time.Now().UTC().Format(time.RFC3339)}) {
		return legacyError(0, AegirErrorCodeTransportError)
	}
	if !c.requestActive(reqCtx) {
		return legacyError(0, AegirErrorCodeTransportError)
	}
	return nil
}
func legacyCorrelation(s, credential string) bool {
	if len(s) > 128 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("_.:-", r)) {
			return false
		}
	}
	if credential != "" {
		for _, part := range strings.Split(credential, ":") {
			if part != "" && strings.Contains(s, part) {
				return false
			}
		}
	}
	return true
}
func legacyJSON(data []byte) (any, error) {
	if !integrationUnicodeJSON(data) {
		return nil, errors.New("invalid JSON Unicode")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	v, e := integrationJSONValue(d, 0)
	if e != nil {
		return nil, e
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, errors.New("trailing JSON")
	}
	return v, nil
}
func legacyShape(v any, t reflect.Type, depth int) bool {
	if depth > 32 {
		return false
	}
	if t.Kind() == reflect.Pointer {
		if v == nil {
			return true
		}
		return legacyShape(v, t.Elem(), depth+1)
	}
	switch t.Kind() {
	case reflect.Struct:
		m, ok := v.(map[string]any)
		if !ok || len(m) < t.NumField() {
			return false
		}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			name := strings.Split(f.Tag.Get("json"), ",")[0]
			x, ok := m[name]
			if !ok || !legacyShape(x, f.Type, depth+1) {
				return false
			}
			if strings.HasSuffix(name, "Id") && x != nil {
				if text, ok := x.(string); !ok || !legacyInput(text, 512, false) {
					return false
				}
			}
			if strings.HasSuffix(name, "AtUtc") && x != nil {
				if _, e := time.Parse(time.RFC3339Nano, x.(string)); e != nil {
					return false
				}
			}
		}
		return true
	case reflect.Slice:
		a, ok := v.([]any)
		if !ok || len(a) > 10000 {
			return false
		}
		for _, x := range a {
			if !legacyShape(x, t.Elem(), depth+1) {
				return false
			}
		}
		return true
	case reflect.Map:
		m, ok := v.(map[string]any)
		if !ok || len(m) > 1000 {
			return false
		}
		for k, x := range m {
			if !legacyInput(k, 512, false) || !legacyShape(x, t.Elem(), depth+1) {
				return false
			}
		}
		return true
	case reflect.String:
		s, ok := v.(string)
		if !ok || !legacyInput(s, 16384, true) {
			return false
		}
		switch t.Name() {
		case "IdentityActionType":
			return s == "LockIdentity" || s == "DisconnectService" || s == "VerifyConnection" || s == "RequestClarity"
		case "IdentityGraphNodeType":
			return legacyEnum(s, "Platform", "Developer", "DeveloperKey", "Application", "Environment", "User", "Device", "Credential", "Challenge", "Token", "AuditAnchor", "PolicyScope", "ExternalService")
		case "IdentityGraphEdgeType":
			return legacyEnum(s, "Owns", "Issued", "Registered", "BelongsTo", "AuthorizedFor", "ScopedTo", "Uses", "PresentedBy", "DerivedFrom", "ApprovedBy", "RevokedBy", "AnchoredBy", "ConnectedTo", "ObservedOn")
		case "IdentityActionStatus":
			return s == "Completed" || s == "Reversed"
		case "ExposureFindingCategory":
			return s == "WeakConnection" || s == "UnknownConnection" || s == "StaleCredential" || s == "HighRiskLinkage"
		case "ExposureFindingSeverity":
			return s == "Low" || s == "Medium" || s == "High"
		}
		return true
	case reflect.Float64:
		n, ok := v.(json.Number)
		if !ok {
			return false
		}
		_, e := n.Float64()
		return e == nil
	}
	return false
}
func legacyGraphBinding(id, subject string) bool {
	return legacyInput(subject, 512, false) && (id == "graph:"+subject || id == "graph:developer:"+subject || id == "graph:user:"+subject)
}
func legacySameString(a, b *string) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}
func legacyHistoryBinding(history []IdentityActionRecord, subject string) bool {
	for _, a := range history {
		if a.SubjectID != subject {
			return false
		}
	}
	return true
}

// Host callbacks cannot be killed in Go. This global budget bounds stranded
// goroutines across clients; excess best-effort diagnostics are skipped, never queued.
var legacyDiagnosticSlots = make(chan struct{}, 4)

func legacyNilAdapter(value any) bool {
	if value == nil {
		return false
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Func, reflect.Map, reflect.Slice, reflect.Chan:
		return v.IsNil()
	}
	return false
}
func (c *AegirSecurityClient) requestActive(ctx context.Context) bool {
	return ctx != nil && ctx.Err() == nil && !c.closed.Load() && c.lifetime != nil && c.lifetime.Err() == nil
}
func (c *AegirSecurityClient) runDiagnostic(ctx context.Context, hook func()) bool {
	if !c.requestActive(ctx) {
		return false
	}
	select {
	case legacyDiagnosticSlots <- struct{}{}:
	default:
		return c.requestActive(ctx)
	}
	done := make(chan struct{})
	go func() { defer func() { _ = recover(); <-legacyDiagnosticSlots; close(done) }(); hook() }()
	select {
	case <-done:
	case <-ctx.Done():
		return false
	case <-c.lifetime.Done():
		return false
	}
	return c.requestActive(ctx)
}
func (c *AegirSecurityClient) emitLog(ctx context.Context, e LogEntry) bool {
	if c.diagnostics == nil || c.diagnostics.Log == nil {
		return c.requestActive(ctx)
	}
	return c.runDiagnostic(ctx, func() { c.diagnostics.Log(e) })
}
func (c *AegirSecurityClient) emitMetric(ctx context.Context, e MetricEvent) bool {
	if c.diagnostics == nil || c.diagnostics.Metric == nil {
		return c.requestActive(ctx)
	}
	return c.runDiagnostic(ctx, func() { c.diagnostics.Metric(e) })
}
func (c *AegirSecurityClient) emitTrace(ctx context.Context, e TraceEvent) bool {
	if c.diagnostics == nil || c.diagnostics.Trace == nil {
		return c.requestActive(ctx)
	}
	return c.runDiagnostic(ctx, func() { c.diagnostics.Trace(e) })
}

func resolveErrorCode(status int, rawBody []byte) AegirErrorCode {
	if len(rawBody) > 0 {
		var payload map[string]any
		if err := json.Unmarshal(rawBody, &payload); err == nil {
			if code, ok := payload["code"].(string); ok && code != "" {
				if legacyKnownCode(AegirErrorCode(code)) {
					return AegirErrorCode(code)
				}
			}
			if code, ok := payload["error"].(string); ok && code != "" {
				if legacyKnownCode(AegirErrorCode(code)) {
					return AegirErrorCode(code)
				}
			}
		}
	}

	switch status {
	case 400:
		return AegirErrorCodeInvalidRequest
	case 401:
		return AegirErrorCodeUnauthorized
	case 403:
		return AegirErrorCodeForbidden
	case 404:
		return AegirErrorCodeNotFound
	case 409:
		return AegirErrorCodeConflict
	case 429:
		return AegirErrorCodeRateLimited
	default:
		if status >= 500 {
			return AegirErrorCodeServerError
		}
		return AegirErrorCodeUnknownError
	}
}

func legacyKnownCode(code AegirErrorCode) bool {
	switch code {
	case AegirErrorCodeInvalidRequest, AegirErrorCodeUnauthorized, AegirErrorCodeForbidden, AegirErrorCodeNotFound, AegirErrorCodeConflict, AegirErrorCodeRateLimited, AegirErrorCodeBudgetExhausted, AegirErrorCodeServerError, AegirErrorCodeTransportError, AegirErrorCodeUnknownError:
		return true
	}
	return false
}

func legacyEnum(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

// The current server serializes known C# enums numerically. Preserve public string
// models while accepting only exact known integer values at the transport boundary.
func legacyEnumNames(name string) []string {
	switch name {
	case "IdentityActionType":
		return []string{"LockIdentity", "DisconnectService", "VerifyConnection", "RequestClarity"}
	case "IdentityActionStatus":
		return []string{"Completed", "Reversed"}
	case "IdentityGraphNodeType":
		return []string{"Platform", "Developer", "DeveloperKey", "Application", "Environment", "User", "Device", "Credential", "Challenge", "Token", "AuditAnchor", "PolicyScope", "ExternalService"}
	case "IdentityGraphEdgeType":
		return []string{"Owns", "Issued", "Registered", "BelongsTo", "AuthorizedFor", "ScopedTo", "Uses", "PresentedBy", "DerivedFrom", "ApprovedBy", "RevokedBy", "AnchoredBy", "ConnectedTo", "ObservedOn"}
	case "ExposureFindingCategory":
		return []string{"WeakConnection", "UnknownConnection", "StaleCredential", "HighRiskLinkage"}
	case "ExposureFindingSeverity":
		return []string{"Low", "Medium", "High"}
	}
	return nil
}
func legacyNormalizeEnums(value any, t reflect.Type) (any, bool) {
	if t.Kind() == reflect.Pointer {
		if value == nil {
			return nil, true
		}
		return legacyNormalizeEnums(value, t.Elem())
	}
	if names := legacyEnumNames(t.Name()); names != nil {
		if number, ok := value.(json.Number); ok {
			n, e := number.Int64()
			if e != nil || n < 1 || n > int64(len(names)) {
				return nil, false
			}
			return names[n-1], true
		}
		text, ok := value.(string)
		return value, ok && legacyEnum(text, names...)
	}
	switch t.Kind() {
	case reflect.Struct:
		m, ok := value.(map[string]any)
		if !ok {
			return nil, false
		}
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			raw, exists := m[name]
			if !exists {
				return nil, false
			}
			normalized, ok := legacyNormalizeEnums(raw, field.Type)
			if !ok {
				return nil, false
			}
			m[name] = normalized
		}
		return m, true
	case reflect.Slice:
		a, ok := value.([]any)
		if !ok {
			return nil, false
		}
		for i, raw := range a {
			n, ok := legacyNormalizeEnums(raw, t.Elem())
			if !ok {
				return nil, false
			}
			a[i] = n
		}
		return a, true
	}
	return value, true
}
