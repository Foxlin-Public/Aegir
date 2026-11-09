//go:build windows

// Copyright Foxlin Industries. Standard-library Windows OS-held journal ownership.
package aegirsecurity

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var journalKernel32 = syscall.NewLazyDLL("kernel32.dll")
var journalLockFileEx = journalKernel32.NewProc("LockFileEx")
var journalUnlockFileEx = journalKernel32.NewProc("UnlockFileEx")

func acquireJournalOwnership(path string) (*os.File, error) {
	root := filepath.VolumeName(path) + `\`
	rootPtr, e := syscall.UTF16PtrFromString(root)
	if e != nil {
		return nil, errors.New("local journal volume required")
	}
	drive, _, _ := journalKernel32.NewProc("GetDriveTypeW").Call(uintptr(unsafe.Pointer(rootPtr)))
	if drive != 3 {
		return nil, errors.New("fixed local journal volume required")
	}
	var fs [260]uint16
	ok, _, _ := journalKernel32.NewProc("GetVolumeInformationW").Call(uintptr(unsafe.Pointer(rootPtr)), 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&fs[0])), uintptr(len(fs)))
	if ok == 0 || !strings.EqualFold(syscall.UTF16ToString(fs[:]), "NTFS") {
		return nil, errors.New("verified NTFS journal storage required")
	}

	if info, e := os.Lstat(path); e == nil && !info.Mode().IsRegular() {
		return nil, errors.New("invalid owner sidecar")
	}
	f, e := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if e != nil {
		return nil, e
	}
	info, e := f.Stat()
	disk, er := os.Lstat(path)
	if e != nil || er != nil || !os.SameFile(info, disk) || !info.Mode().IsRegular() {
		f.Close()
		return nil, errors.New("owner identity changed")
	}
	var overlap syscall.Overlapped
	result, _, callErr := journalLockFileEx.Call(f.Fd(), 3, 0, 1, 0, uintptr(unsafe.Pointer(&overlap)))
	if result == 0 {
		f.Close()
		return nil, callErr
	}
	return f, nil
}
func releaseJournalOwnership(f *os.File) error {
	var overlap syscall.Overlapped
	r, _, e := journalUnlockFileEx.Call(f.Fd(), 0, 1, 0, uintptr(unsafe.Pointer(&overlap)))
	ce := f.Close()
	if r == 0 {
		return e
	}
	return ce
}

// Retry only the same already-flushed atomic replacement, never the transaction.
// Windows scanners may briefly deny delete sharing. Ownership remains held;
// exhaustion/non-sharing errors fail closed without advancing in-memory state.
func replaceJournalFile(temporary, target string) error {
	return journalReplaceBounded(func() error { return os.Rename(temporary, target) }, time.Now, time.Sleep)
}
func journalReplaceBounded(move func() error, now func() time.Time, pause func(time.Duration)) error {
	deadline := now().Add(200 * time.Millisecond)
	for {
		e := move()
		if e == nil {
			return nil
		}
		var code syscall.Errno
		if !errors.As(e, &code) || (code != 5 && code != 32 && code != 33) || !now().Before(deadline) {
			return e
		}
		remaining := deadline.Sub(now())
		if remaining <= 0 {
			return e
		}
		if remaining > 10*time.Millisecond {
			remaining = 10 * time.Millisecond
		}
		pause(remaining)
	}
}
