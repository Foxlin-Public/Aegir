// Copyright Foxlin Industries. Local, unreleased integration runner.
// Config and stdin are private: stdout never contains tickets or credentials.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	sdk "foxlin/aegir-security-go"
	"os"
	"time"
)

type configuration struct {
	sdk.IntegrationConfig
	JournalPath string `json:"journalPath"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	TimeoutMS   int    `json:"timeoutMs"`
}
type command struct {
	RequestID   string `json:"requestId"`
	Op          string `json:"op"`
	Operation   string `json:"operation"`
	Acknowledge *bool  `json:"acknowledge"`
	ChallengeID string `json:"challengeId"`
	TOTPCode    string `json:"totpCode"`
	TimeoutMS   int    `json:"timeoutMs"`
}

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "Aegir integration runner failed; inspect private configuration and local service state.")
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) != 2 {
		return fmt.Errorf("private configuration path required")
	}
	bytes, e := os.ReadFile(os.Args[1])
	if e != nil || len(bytes) > 65536 {
		return fmt.Errorf("configuration unavailable")
	}
	var config configuration
	if json.Unmarshal(bytes, &config) != nil {
		return fmt.Errorf("invalid configuration")
	}
	if config.TimeoutMS > 0 {
		config.Timeout = time.Duration(config.TimeoutMS) * time.Millisecond
	}
	journal, e := sdk.NewFileAuthorizationJournal(config.JournalPath)
	if e != nil {
		return e
	}
	client, e := sdk.NewAuthorizationIntegration(config.IntegrationConfig, journal)
	if e != nil {
		journal.Close()
		return e
	}
	defer client.Close()
	ticket := ""
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 1024), 65536)
	output := json.NewEncoder(os.Stdout)
	for scanner.Scan() {
		var cmd command
		result := map[string]any{"ok": false}
		if json.Unmarshal(scanner.Bytes(), &cmd) != nil {
			result["reason"] = "invalid_command"
			if e = output.Encode(result); e != nil {
				return e
			}
			continue
		}
		result["requestId"] = cmd.RequestID
		timeout := 30 * time.Second
		if cmd.TimeoutMS > 0 && cmd.TimeoutMS < 30000 {
			timeout = time.Duration(cmd.TimeoutMS) * time.Millisecond
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		switch cmd.Op {
		case "authenticate":
			ticket = ""
			auth, er := client.AuthenticateFresh(ctx, config.Username, config.Password, cmd.ChallengeID, cmd.TOTPCode)
			if er != nil {
				result["reason"] = "authentication_failed"
			} else if auth.MFARequired {
				result["ok"] = true
				result["mfaRequired"] = true
				result["challengeId"] = auth.ChallengeID
			} else {
				ticket = auth.AccessToken
				result["ok"] = true
				result["mfaRequired"] = false
			}
		case "reconnect":
			if er := client.Reconnect(ctx); er != nil {
				result["reason"] = "reconciliation_failed"
			} else {
				result["ok"] = true
			}
		case "poll":
			ack := cmd.Acknowledge == nil || *cmd.Acknowledge
			if er := client.PollWithAcknowledgment(ctx, ack); er != nil {
				result["reason"] = "poll_failed"
			} else {
				result["ok"] = true
			}
		case "check":
			decision := client.Authorize(ctx, ticket, cmd.Operation, "")
			result["ok"] = true
			result["isAuthorized"] = decision.IsAuthorized
			result["reason"] = decision.Reason
		case "execute":
			effects := 0
			decision, er := client.ExecuteProtected(ctx, ticket, cmd.Operation, "", func(ct context.Context) error {
				if _, er := client.BeforeCommit(ct, ticket, cmd.Operation, ""); er != nil {
					return er
				}
				effects++
				return nil
			})
			result["ok"] = er == nil
			result["isAuthorized"] = decision.IsAuthorized && er == nil
			result["callbackCount"] = effects
			result["reason"] = decision.Reason
		case "disconnect":
			client.Disconnect()
			result["ok"] = true
		case "state":
			stats, er := journal.Stats(ctx)
			if er != nil {
				result["reason"] = "journal_unavailable"
			} else {
				result["ok"] = true
				result["receipts"] = stats.Receipts
				result["effects"] = stats.Effects
				result["connected"] = stats.Connected
			}
		case "close":
			er := client.Close()
			result["ok"] = er == nil
			cancel()
			if e = output.Encode(result); e != nil {
				return e
			}
			return nil
		default:
			result["reason"] = "unsupported_command"
		}
		cancel()
		if e = output.Encode(result); e != nil {
			return e
		}
	}
	return scanner.Err()
}
