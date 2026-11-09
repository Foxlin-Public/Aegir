//go:build !windows && !linux

package aegirsecurity

import (
	"errors"
	"os"
)

func acquireJournalOwnership(string) (*os.File, error) {
	return nil, errors.New("journal OS ownership unsupported")
}
func releaseJournalOwnership(f *os.File) error { return f.Close() }

func replaceJournalFile(temporary, target string) error { return os.Rename(temporary, target) }
