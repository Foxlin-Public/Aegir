package aegirsecurity

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

type AegirSecurityClient struct {
	baseURL      string
	configKey    string
	developerKey string
	httpClient   HTTPDoer
	diagnostics  *DiagnosticsHooks
}

type ClientOptions struct {
	BaseURL      string
	ConfigKey    string
	DeveloperKey string
	HTTPClient   HTTPDoer
	Diagnostics  *DiagnosticsHooks
}

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

func NewAegirSecurityClient(baseURL, configKey, developerKey string, httpClient HTTPDoer) *AegirSecurityClient {
	return NewAegirSecurityClientWithOptions(ClientOptions{
		BaseURL:      baseURL,
		ConfigKey:    configKey,
		DeveloperKey: developerKey,
		HTTPClient:   httpClient,
	})
}

func NewAegirSecurityClientWithOptions(options ClientOptions) *AegirSecurityClient {
	if options.HTTPClient == nil {
		options.HTTPClient = http.DefaultClient
	}

	return &AegirSecurityClient{
		baseURL:      strings.TrimRight(options.BaseURL, "/"),
		configKey:    options.ConfigKey,
		developerKey: options.DeveloperKey,
		httpClient:   options.HTTPClient,
		diagnostics:  options.Diagnostics,
	}
}

func (c *AegirSecurityClient) ScanIdentity(subjectID string) (*ScanIdentityResult, error) {
	var payload ScanIdentityResult
	if err := c.request("scanIdentity", "/security/scan/"+url.PathEscape(subjectID), http.MethodGet, nil, &payload); err != nil {
		return nil, err
	}
	return &payload, nil
}

func (c *AegirSecurityClient) GetIdentityGraph(subjectID string) (*IdentityGraphSnapshot, error) {
	var payload IdentityGraphSnapshot
	if err := c.request("getIdentityGraph", "/security/graphs/"+url.PathEscape(subjectID), http.MethodGet, nil, &payload); err != nil {
		return nil, err
	}
	return &payload, nil
}

func (c *AegirSecurityClient) GetIdentityGraphJSON(subjectID string) (string, error) {
	payload, err := c.GetIdentityGraph(subjectID)
	if err != nil {
		return "", err
	}

	buffer, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	return string(buffer), nil
}

func (c *AegirSecurityClient) GetExposureSummary(subjectID string) (*ExposureSummary, error) {
	var payload ExposureSummary
	if err := c.request("getExposureSummary", "/security/exposure/"+url.PathEscape(subjectID), http.MethodGet, nil, &payload); err != nil {
		return nil, err
	}
	return &payload, nil
}

func (c *AegirSecurityClient) PerformAction(action PerformIdentityActionRequest) (*IdentityActionRecord, error) {
	var payload IdentityActionRecord
	if err := c.request("performAction", "/security/actions", http.MethodPost, action, &payload); err != nil {
		return nil, err
	}
	return &payload, nil
}

func (c *AegirSecurityClient) ReverseAction(actionID string, reason *string) (*IdentityActionRecord, error) {
	suffix := ""
	if reason != nil {
		suffix = "?reason=" + url.QueryEscape(*reason)
	}

	var payload IdentityActionRecord
	if err := c.request("reverseAction", "/security/actions/"+url.PathEscape(actionID)+"/reverse"+suffix, http.MethodPost, nil, &payload); err != nil {
		return nil, err
	}
	return &payload, nil
}

func (c *AegirSecurityClient) GetActionHistory(subjectID string) ([]IdentityActionRecord, error) {
	var payload []IdentityActionRecord
	if err := c.request("getActionHistory", "/security/actions/history/"+url.PathEscape(subjectID), http.MethodGet, nil, &payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func (c *AegirSecurityClient) request(operation, path, method string, body any, target any) error {
	var reader io.Reader
	if body != nil {
		buffer, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(buffer)
	}

	req, err := http.NewRequest(method, c.baseURL+"/v1"+path, reader)
	if err != nil {
		return err
	}

	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.configKey != "" {
		req.Header.Set("X-Aegir-Config-Key", c.configKey)
	}
	if c.developerKey != "" {
		req.Header.Set("X-Aegir-Developer-Key", c.developerKey)
	}

	c.emitTrace(TraceEvent{
		TraceName:     "request.start",
		Operation:     operation,
		TracePhase:    "request.start",
		OccurredAtUTC: time.Now().UTC().Format(time.RFC3339),
		Metadata:      map[string]string{"path": path, "method": method},
	})
	c.emitLog(LogEntry{
		Level:         "information",
		EventName:     "request.start",
		Message:       "Starting " + operation + ".",
		Operation:     operation,
		OccurredAtUTC: time.Now().UTC().Format(time.RFC3339),
		Metadata:      map[string]string{"path": path, "method": method},
	})

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.emitMetric(MetricEvent{
			MetricName:    "aegir.client.request.duration",
			Value:         0,
			Unit:          "ms",
			ObservedAtUTC: time.Now().UTC().Format(time.RFC3339),
			Dimensions:    map[string]string{"operation": operation, "status": "0", "errorCode": string(AegirErrorCodeTransportError)},
		})
		c.emitTrace(TraceEvent{
			TraceName:     "request.error",
			Operation:     operation,
			TracePhase:    "request.error",
			OccurredAtUTC: time.Now().UTC().Format(time.RFC3339),
			Metadata:      map[string]string{"errorCode": string(AegirErrorCodeTransportError)},
		})
		return &AegirSecurityError{Status: 0, Code: AegirErrorCodeTransportError}
	}
	defer resp.Body.Close()

	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	correlationID := resp.Header.Get("X-Correlation-Id")
	code := resolveErrorCode(resp.StatusCode, rawBody)
	c.emitMetric(MetricEvent{
		MetricName:    "aegir.client.request.duration",
		Value:         0,
		Unit:          "ms",
		ObservedAtUTC: time.Now().UTC().Format(time.RFC3339),
		Dimensions:    map[string]string{"operation": operation, "status": http.StatusText(resp.StatusCode), "errorCode": string(code)},
	})

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		c.emitLog(LogEntry{
			Level:         "error",
			EventName:     "request.error",
			Message:       (&AegirSecurityError{Status: resp.StatusCode}).Error(),
			Operation:     operation,
			CorrelationID: correlationID,
			OccurredAtUTC: time.Now().UTC().Format(time.RFC3339),
			Metadata:      map[string]string{"status": http.StatusText(resp.StatusCode), "errorCode": string(code)},
		})
		c.emitTrace(TraceEvent{
			TraceName:     "request.error",
			Operation:     operation,
			TracePhase:    "request.error",
			CorrelationID: correlationID,
			OccurredAtUTC: time.Now().UTC().Format(time.RFC3339),
			Metadata:      map[string]string{"status": http.StatusText(resp.StatusCode), "errorCode": string(code)},
		})
		return &AegirSecurityError{Status: resp.StatusCode, Code: code, CorrelationID: correlationID, Body: string(rawBody)}
	}

	c.emitLog(LogEntry{
		Level:         "information",
		EventName:     "request.complete",
		Message:       "Completed " + operation + ".",
		Operation:     operation,
		CorrelationID: correlationID,
		OccurredAtUTC: time.Now().UTC().Format(time.RFC3339),
		Metadata:      map[string]string{"status": http.StatusText(resp.StatusCode)},
	})
	c.emitTrace(TraceEvent{
		TraceName:     "request.complete",
		Operation:     operation,
		TracePhase:    "request.complete",
		CorrelationID: correlationID,
		OccurredAtUTC: time.Now().UTC().Format(time.RFC3339),
		Metadata:      map[string]string{"status": http.StatusText(resp.StatusCode)},
	})

	if len(rawBody) == 0 || target == nil {
		return nil
	}

	return json.Unmarshal(rawBody, target)
}

func (c *AegirSecurityClient) emitLog(entry LogEntry) {
	if c.diagnostics != nil && c.diagnostics.Log != nil {
		c.diagnostics.Log(entry)
	}
}

func (c *AegirSecurityClient) emitMetric(event MetricEvent) {
	if c.diagnostics != nil && c.diagnostics.Metric != nil {
		c.diagnostics.Metric(event)
	}
}

func (c *AegirSecurityClient) emitTrace(event TraceEvent) {
	if c.diagnostics != nil && c.diagnostics.Trace != nil {
		c.diagnostics.Trace(event)
	}
}

func resolveErrorCode(status int, rawBody []byte) AegirErrorCode {
	if len(rawBody) > 0 {
		var payload map[string]any
		if err := json.Unmarshal(rawBody, &payload); err == nil {
			if code, ok := payload["code"].(string); ok && code != "" {
				return AegirErrorCode(code)
			}
			if code, ok := payload["error"].(string); ok && code != "" {
				return AegirErrorCode(code)
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
