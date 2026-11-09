// Copyright Foxlin Industries. Genuine-server legacy consumer, private config only.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	aegir "foxlin/aegir-security-go"
	"io"
	"os"
	"time"
)

type config struct {
	APIBaseURL        string `json:"apiBaseUrl"`
	DeveloperKey      string `json:"developerKey"`
	CertificateSHA256 string `json:"certificateSha256"`
	SubjectID         string `json:"subjectId"`
	TimeoutMs         int    `json:"timeoutMs"`
}

func emit(op string, ok bool) {
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"op": op, "ok": ok})
}
func run() error {
	if len(os.Args) != 2 {
		return fmt.Errorf("private configuration path required")
	}
	f, e := os.Open(os.Args[1])
	if e != nil {
		return fmt.Errorf("private configuration unavailable")
	}
	data, e := io.ReadAll(io.LimitReader(f, 32769))
	f.Close()
	if e != nil || len(data) > 32768 {
		return fmt.Errorf("invalid private configuration")
	}
	var cfg config
	if json.Unmarshal(data, &cfg) != nil || cfg.SubjectID == "" {
		return fmt.Errorf("invalid private configuration")
	}
	timeout := 15 * time.Second
	if cfg.TimeoutMs != 0 {
		timeout = time.Duration(cfg.TimeoutMs) * time.Millisecond
	}
	c := aegir.NewAegirSecurityClientWithOptions(aegir.ClientOptions{BaseURL: cfg.APIBaseURL, DeveloperKey: cfg.DeveloperKey, CertificateSHA256: cfg.CertificateSHA256, Timeout: timeout})
	defer c.Close()
	ctx := context.Background()
	if _, e = c.ScanIdentityContext(ctx, cfg.SubjectID); e != nil {
		emit("scan", false)
		return e
	}
	emit("scan", true)
	if _, e = c.GetIdentityGraphContext(ctx, cfg.SubjectID); e != nil {
		emit("graph", false)
		return e
	}
	emit("graph", true)
	if _, e = c.GetIdentityGraphJSONContext(ctx, cfg.SubjectID); e != nil {
		emit("graphJson", false)
		return e
	}
	emit("graphJson", true)
	if _, e = c.GetExposureSummaryContext(ctx, cfg.SubjectID); e != nil {
		emit("exposure", false)
		return e
	}
	emit("exposure", true)
	record, e := c.PerformActionContext(ctx, aegir.PerformIdentityActionRequest{SubjectID: cfg.SubjectID, ActionType: aegir.IdentityActionTypeRequestClarity})
	if e != nil {
		emit("performAction", false)
		return e
	}
	emit("performAction", true)
	if _, e = c.ReverseActionContext(ctx, record.ActionID, nil); e != nil {
		emit("reverseAction", false)
		return e
	}
	emit("reverseAction", true)
	history, e := c.GetActionHistoryContext(ctx, cfg.SubjectID)
	if e != nil {
		emit("history", false)
		return e
	}
	found := false
	for _, item := range history {
		if item.ActionID == record.ActionID && item.Status == aegir.IdentityActionStatusReversed {
			found = true
		}
	}
	emit("history", found)
	if !found {
		return fmt.Errorf("expected action history absent")
	}
	return nil
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "Legacy security scenario failed; no credential or upstream body logged.")
		os.Exit(1)
	}
}
