//go:build linux

// Copyright Foxlin Industries. Standard-library Linux advisory ownership.
package aegirsecurity

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

func acquireJournalOwnership(path string) (*os.File, error) {
	var storage syscall.Statfs_t
	if e := syscall.Statfs(filepath.Dir(path), &storage); e != nil {
		return nil, e
	}
	switch uint64(storage.Type) {
	case 0xEF53, 0x01021994, 0x794c7630:
	default:
		return nil, errors.New("journal filesystem has not been qualified for local locks")
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
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		f.Close()
		return nil, e
	}
	return f, nil
}
func releaseJournalOwnership(f *os.File) error {
	e := syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	ce := f.Close()
	if e != nil {
		return e
	}
	return ce
}

func replaceJournalFile(temporary, target string) error { return os.Rename(temporary, target) }
