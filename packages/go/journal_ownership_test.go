// Copyright Foxlin Industries. Actual child process ownership/crash acceptance.
package aegirsecurity

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestJournalOwnershipChild(t *testing.T) {
	mode := os.Getenv("AEGIR_OWNERSHIP_TEST_CHILD")
	if mode == "" {
		return
	}
	path := os.Getenv("AEGIR_OWNERSHIP_TEST_PATH")
	j, e := NewFileAuthorizationJournal(path)
	if e != nil {
		fmt.Println("DENIED")
		return
	}
	if mode == "seed" {
		ctx := context.Background()
		if e = j.Bind(ctx, strings.Repeat("a", 64)); e != nil {
			os.Exit(21)
		}
		if e = j.ApplySnapshot(ctx, AuthorizationSnapshot{SnapshotID: "seed", Groups: []AuthorizationSnapshotGroup{{GroupID: "g", GroupVersion: 1, Subjects: []AuthorizationSnapshotSubject{}}}}); e != nil {
			os.Exit(22)
		}
		if _, e = j.Apply(ctx, []AuthorizationNotification{{ProtocolVersion: 1, TransactionID: "tx", EventID: "revoke", GroupID: "g", EventType: "revoked", GroupVersion: 2}}); e != nil {
			os.Exit(23)
		}
		if e = j.SetConnected(ctx, true); e != nil {
			os.Exit(24)
		}
	}
	fmt.Println("OWNED")
	os.Stdout.Sync()
	_, _ = bufio.NewReader(os.Stdin).ReadByte()
	_ = j.Close()
}

type journalChild struct {
	cmd   *exec.Cmd
	stdin io.WriteCloser
	ready chan string
}

func startJournalChild(t *testing.T, path, mode string) *journalChild {
	t.Helper()
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(exe, "-test.run=^TestJournalOwnershipChild$")
	cmd.Env = append(os.Environ(), "AEGIR_OWNERSHIP_TEST_CHILD="+mode, "AEGIR_OWNERSHIP_TEST_PATH="+path)
	out, e := cmd.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	stdin, e := cmd.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	child := &journalChild{cmd: cmd, stdin: stdin, ready: make(chan string, 1)}
	go func() {
		scanner := bufio.NewScanner(out)
		for scanner.Scan() {
			line := scanner.Text()
			if line == "OWNED" || line == "DENIED" {
				child.ready <- line
				return
			}
		}
		child.ready <- "FAILED"
	}()
	t.Cleanup(func() {
		_ = stdin.Close()
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	return child
}
func waitJournalChild(t *testing.T, c *journalChild) string {
	t.Helper()
	select {
	case s := <-c.ready:
		return s
	case <-time.After(5 * time.Second):
		t.Fatal("child readiness timeout")
	}
	return ""
}
func TestJournalHardKillRecoveryPreservesDedupAndRevocation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal")
	child := startJournalChild(t, path, "seed")
	if waitJournalChild(t, child) != "OWNED" {
		t.Fatal("first owner denied")
	}
	if e := child.cmd.Process.Kill(); e != nil {
		t.Fatal(e)
	}
	if e := child.cmd.Wait(); e == nil {
		t.Fatal("hard termination not observed")
	}
	j, e := NewFileAuthorizationJournal(path)
	if e != nil {
		t.Fatal("OS did not release crashed ownership:", e)
	}
	defer j.Close()
	ctx := context.Background()
	stats, _ := j.Stats(ctx)
	if stats.Connected || stats.Effects != 1 || stats.Receipts != 1 {
		t.Fatal("crash lost durable state or resumed without reconciliation")
	}
	replay, e := j.Apply(ctx, []AuthorizationNotification{{ProtocolVersion: 1, TransactionID: "tx", EventID: "revoke", GroupID: "g", EventType: "revoked", GroupVersion: 2}})
	if e != nil || replay.NewEffects != 0 {
		t.Fatal("lost ACK replay duplicated effect")
	}
	late, e := j.Apply(ctx, []AuthorizationNotification{{ProtocolVersion: 1, TransactionID: "tx", EventID: "old-grant", GroupID: "g", EventType: "granted", GroupVersion: 1}})
	if e != nil || late.NewEffects != 0 {
		t.Fatal("late grant acquired effect")
	}
	if e = j.ApplySnapshot(ctx, AuthorizationSnapshot{SnapshotID: "old", Groups: []AuthorizationSnapshotGroup{{GroupID: "g", GroupVersion: 1, Subjects: []AuthorizationSnapshotSubject{}}}}); e == nil {
		t.Fatal("rollback snapshot accepted")
	}
	if _, e = os.OpenFile(path+".lock", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600); e == nil {
		t.Fatal("D1 downgrade bypassed guard")
	}
}
func TestJournalConcurrentRecoveryExactlyOneOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal")
	seed, e := NewFileAuthorizationJournal(path)
	if e != nil {
		t.Fatal(e)
	}
	seed.Close()
	a := startJournalChild(t, path, "hold")
	b := startJournalChild(t, path, "hold")
	one, two := waitJournalChild(t, a), waitJournalChild(t, b)
	if !(one == "OWNED" && two == "DENIED" || one == "DENIED" && two == "OWNED") {
		t.Fatal("competing recoveries did not select exactly one owner", one, two)
	}
}
func TestJournalLegacyAndPartialGuardNeverRemoved(t *testing.T) {
	for _, guard := range []string{"", "partial", "Aegir journal ownership v2; OS lock required"} {
		path := filepath.Join(t.TempDir(), "journal")
		original := []byte(guard)
		if e := os.WriteFile(path+".lock", original, 0600); e != nil {
			t.Fatal(e)
		}
		if j, e := NewFileAuthorizationJournal(path); e == nil {
			j.Close()
			t.Fatal("legacy/partial guard adopted")
		}
		after, _ := os.ReadFile(path + ".lock")
		if string(after) != guard {
			t.Fatal("legacy guard changed")
		}
	}
}
func TestJournalMissingEstablishedCorruptTruncatedAndCapacity(t *testing.T) {
	ctx := context.Background()
	for _, mode := range []string{"missing", "truncated", "checksum", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "journal")
			j, e := NewFileAuthorizationJournal(path)
			if e != nil {
				t.Fatal(e)
			}
			j.Close()
			data, _ := os.ReadFile(path)
			switch mode {
			case "missing":
				os.Remove(path)
			case "truncated":
				data = data[:len(data)/2]
				os.WriteFile(path, data, 0600)
			case "checksum":
				data[20] = '0'
				os.WriteFile(path, data, 0600)
			case "oversized":
				data = []byte(strings.Repeat("x", (16<<20)+1))
				os.WriteFile(path, data, 0600)
			}
			if reopened, e := NewFileAuthorizationJournal(path); e == nil {
				reopened.Close()
				t.Fatal("invalid established state reset")
			}
			after, er := os.ReadFile(path)
			if mode == "missing" {
				if !os.IsNotExist(er) {
					t.Fatal("missing journal silently recreated")
				}
			} else if string(after) != string(data) {
				t.Fatal("invalid journal overwritten")
			}
		})
	}
	path := filepath.Join(t.TempDir(), "journal")
	j, e := NewFileAuthorizationJournal(path)
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256([]byte("receipt"))
	for i := 0; i < 100000; i++ {
		j.state.Receipts[fmt.Sprint(i)] = hex.EncodeToString(sum[:])
	}
	j.state.Effects = 100000
	if e = j.persist(j.state); e != nil {
		t.Fatal(e)
	}
	j.Close()
	j, e = NewFileAuthorizationJournal(path)
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	if _, e = j.Apply(ctx, []AuthorizationNotification{{ProtocolVersion: 1, TransactionID: "tx", EventID: "beyond-capacity", GroupID: "g", EventType: "revoked", GroupVersion: 1}}); e == nil {
		t.Fatal("capacity evicted old receipt")
	}
	stats, _ := j.Stats(ctx)
	if stats.Receipts != 100000 {
		t.Fatal("capacity mutated state")
	}
	body, _ := os.ReadFile(path)
	var envelope fileAuthorizationEnvelope
	if json.Unmarshal(body, &envelope) != nil {
		t.Fatal("capacity file corrupt")
	}
}

func TestJournalUnsupportedOwnerAndNonlocalPathFailClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal")
	if e := os.Mkdir(path+".owner", 0700); e != nil {
		t.Fatal(e)
	}
	if j, e := NewFileAuthorizationJournal(path); e == nil {
		j.Close()
		t.Fatal("nonregular ownership storage accepted")
	}
	if _, e := os.Stat(path); !os.IsNotExist(e) {
		t.Fatal("unsupported owner created journal")
	}
	if runtime.GOOS == "windows" {
		if j, e := NewFileAuthorizationJournal(`\\nonexistent-invalid-local-only-test\share\journal`); e == nil {
			j.Close()
			t.Fatal("UNC path accepted")
		}
	}
}
