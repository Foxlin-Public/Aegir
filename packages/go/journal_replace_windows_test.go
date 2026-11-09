//go:build windows

// Copyright Foxlin Industries. Deterministic bounded retry/exhaustion policy tests.
package aegirsecurity

import (
	"errors"
	"syscall"
	"testing"
	"time"
)

func TestJournalWindowsAtomicReplaceRetryIsBounded(t *testing.T) {
	for _, code := range []syscall.Errno{5, 32, 33} {
		clock := time.Unix(0, 0)
		calls := 0
		e := journalReplaceBounded(func() error {
			calls++
			if calls == 1 {
				return code
			}
			return nil
		}, func() time.Time { return clock }, func(d time.Duration) { clock = clock.Add(d) })
		if e != nil || calls != 2 {
			t.Fatal("transient atomic replace not retried")
		}
		calls = 0
		start := clock
		e = journalReplaceBounded(func() error { calls++; return code }, func() time.Time { return clock }, func(d time.Duration) { clock = clock.Add(d) })
		if !errors.Is(e, code) || clock.Sub(start) > 200*time.Millisecond || calls > 22 {
			t.Fatal("atomic replace retry exceeded bound")
		}
	}
	calls := 0
	e := journalReplaceBounded(func() error { calls++; return syscall.Errno(2) }, time.Now, func(time.Duration) { t.Fatal("nonsharing failure retried") })
	if !errors.Is(e, syscall.Errno(2)) || calls != 1 {
		t.Fatal("nonsharing error changed")
	}
}
