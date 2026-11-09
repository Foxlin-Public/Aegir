// Copyright Foxlin Industries. Local durable RC1 journal adapter.
package aegirsecurity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var authorizationKnownEvents = map[string]bool{"granted": true, "revoked": true, "adminGranted": true, "adminRevoked": true, "permissionChanged": true, "licenseGranted": true, "licenseRevoked": true, "membershipChanged": true, "suspended": true, "restored": true, "groupPolicyChanged": true}

type fileAuthorizationState struct {
	Format    int               `json:"format"`
	Binding   string            `json:"binding"`
	Connected bool              `json:"connected"`
	Receipts  map[string]string `json:"receipts"`
	Versions  map[string]int64  `json:"versions"`
	Effects   int               `json:"effects"`
}
type fileAuthorizationEnvelope struct {
	SHA256 string          `json:"sha256"`
	State  json.RawMessage `json:"state"`
}

// FileAuthorizationJournal is a bounded local atomic-replace adapter. It stores
// only event receipt hashes, monotonic versions and invalidation counts, never
// credentials or access grants. Parent directory must be private to the host.
// A stable OS-held sidecar releases on process death. A persistent versioned
// .lock guard prevents older O_EXCL clients bypassing ownership. Unmarked legacy
// locks are never adopted or deleted; stopped operator validation is required.
// Storage/rename/fsync failure aborts the consumer; arbitrary business effects are
// outside this journal. Journal capacity exhaustion requires host reconciliation
// into another durable adapter; receipts are never silently evicted.
type FileAuthorizationJournal struct {
	mu     sync.Mutex
	path   string
	lock   *os.File
	state  fileAuthorizationState
	closed bool
}

func NewFileAuthorizationJournal(path string) (*FileAuthorizationJournal, error) {
	absolute, e := filepath.Abs(path)
	if e != nil || path == "" {
		return nil, errors.New("journal path required")
	}
	if strings.HasPrefix(absolute, `\\`) {
		return nil, errors.New("local private journal storage required")
	}
	parent := filepath.Dir(absolute)
	if e = os.MkdirAll(parent, 0700); e != nil {
		return nil, errors.New("journal directory unavailable")
	}
	if info, er := os.Lstat(absolute); er == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return nil, errors.New("journal must be a regular private file")
	}
	if info, er := os.Lstat(parent); er != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("private journal directory required")
	}
	owner, e := acquireJournalOwnership(absolute + ".owner")
	if e != nil {
		return nil, errors.New("journal is owned or OS locking unavailable")
	}
	j := &FileAuthorizationJournal{path: absolute, lock: owner, state: fileAuthorizationState{Format: 1, Receipts: map[string]string{}, Versions: map[string]int64{}}}
	fail := func(err error) (*FileAuthorizationJournal, error) {
		_ = releaseJournalOwnership(owner)
		return nil, err
	}
	established, e := installJournalGuard(absolute + ".lock")
	if e != nil {
		return fail(e)
	}
	file, er := os.Open(absolute)
	if er == nil {
		info, e := file.Stat()
		if e != nil || !info.Mode().IsRegular() || info.Size() > 16<<20 {
			file.Close()
			return fail(errors.New("journal exceeds capacity or is not regular"))
		}
		data, e := io.ReadAll(io.LimitReader(file, (16<<20)+1))
		closeErr := file.Close()
		if e != nil || closeErr != nil || len(data) > 16<<20 {
			return fail(errors.New("journal bounded read failed"))
		}
		if parsed, parseErr := integrationObject(data); parseErr != nil || !journalEnvelopeShape(parsed) {
			return fail(errors.New("corrupt journal"))
		}
		var envelope fileAuthorizationEnvelope
		if json.Unmarshal(data, &envelope) != nil {
			return fail(errors.New("corrupt journal"))
		}
		digest := sha256.Sum256(envelope.State)
		if envelope.SHA256 != hex.EncodeToString(digest[:]) || json.Unmarshal(envelope.State, &j.state) != nil || j.state.Format != 1 || j.state.Receipts == nil || j.state.Versions == nil || j.state.Effects < 0 || len(j.state.Receipts) > 100000 || len(j.state.Versions) > 10000 {
			return fail(errors.New("journal checksum or format mismatch"))
		}
		for id, hash := range j.state.Receipts {
			decoded, er := hex.DecodeString(hash)
			if !integrationBound(id, 512) || er != nil || len(decoded) != 32 {
				return fail(errors.New("invalid journal receipt"))
			}
		}
		for group, version := range j.state.Versions {
			if !integrationBound(group, 512) || version < 0 {
				return fail(errors.New("invalid journal version"))
			}
		}
	} else if !os.IsNotExist(er) || established {
		return fail(errors.New("established journal missing or unreadable"))
	}
	j.state.Connected = false
	if e = j.persist(j.state); e != nil {
		return fail(e)
	}
	return j, nil
}

func (j *FileAuthorizationJournal) persist(state fileAuthorizationState) error {
	body, e := json.Marshal(state)
	if e != nil {
		return errors.New("journal encoding failed")
	}
	digest := sha256.Sum256(body)
	data, e := json.Marshal(fileAuthorizationEnvelope{SHA256: hex.EncodeToString(digest[:]), State: body})
	if e != nil || len(data) > 16<<20 {
		return errors.New("journal capacity exceeded")
	}
	temp, e := os.CreateTemp(filepath.Dir(j.path), ".aegir-journal-*.tmp")
	if e != nil {
		return errors.New("journal temporary file unavailable")
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if e = temp.Chmod(0600); e == nil {
		_, e = temp.Write(data)
	}
	if e == nil {
		e = temp.Sync()
	}
	closeError := temp.Close()
	if e != nil || closeError != nil {
		return errors.New("journal durable write failed")
	}
	// Same-directory replacement keeps the previous complete state intact until
	// the new checksum-protected state is ready. Any rename error is fail-closed.
	if e = replaceJournalFile(tempName, j.path); e != nil {
		return errors.New("journal atomic replacement failed")
	}
	// Directory sync is supported on Unix. Windows refuses directory Sync; file
	// Sync and replacement protect process-crash consistency, not arbitrary power loss.
	if directory, er := os.Open(filepath.Dir(j.path)); er == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
	return nil
}

func cloneAuthorizationState(s fileAuthorizationState) fileAuthorizationState {
	result := fileAuthorizationState{Format: 1, Binding: s.Binding, Connected: s.Connected, Effects: s.Effects, Receipts: map[string]string{}, Versions: map[string]int64{}}
	for k, v := range s.Receipts {
		result.Receipts[k] = v
	}
	for k, v := range s.Versions {
		result.Versions[k] = v
	}
	return result
}
func validAuthorizationEvent(e AuthorizationNotification) bool {
	return e.ProtocolVersion == 1 && authorizationKnownEvents[e.EventType] && e.GroupVersion >= 1 && integrationBound(e.TransactionID, 512) && integrationBound(e.EventID, 512) && integrationBound(e.GroupID, 512) && (e.UserID == nil || integrationBound(*e.UserID, 512))
}

// Bind prevents accidental journal sharing between different API/org/app streams.
// A credential rotation retains the binding because its secret is never persisted.
func (j *FileAuthorizationJournal) Bind(ctx context.Context, binding string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return errors.New("journal closed")
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	decoded, e := hex.DecodeString(binding)
	if e != nil || len(decoded) != 32 {
		return errors.New("invalid journal stream binding")
	}
	if j.state.Binding != "" && j.state.Binding != binding {
		return errors.New("journal belongs to another application stream")
	}
	if j.state.Binding == "" && (len(j.state.Receipts) > 0 || len(j.state.Versions) > 0) {
		return errors.New("unbound historical journal requires operator reconciliation")
	}
	next := cloneAuthorizationState(j.state)
	next.Binding = binding
	next.Connected = false
	if e = j.persist(next); e != nil {
		return e
	}
	j.state = next
	return nil
}

func (j *FileAuthorizationJournal) Apply(ctx context.Context, events []AuthorizationNotification) (AuthorizationApplyResult, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return AuthorizationApplyResult{}, errors.New("journal closed")
	}
	if e := ctx.Err(); e != nil {
		return AuthorizationApplyResult{}, e
	}
	if len(events) > 100 {
		return AuthorizationApplyResult{}, errors.New("event batch exceeds 100")
	}
	next := cloneAuthorizationState(j.state)
	effects := 0
	for _, item := range events {
		if !validAuthorizationEvent(item) {
			return AuthorizationApplyResult{RequiresSnapshot: true}, nil
		}
		body, _ := json.Marshal(item)
		sum := sha256.Sum256(body)
		hash := hex.EncodeToString(sum[:])
		if seen, ok := next.Receipts[item.EventID]; ok {
			if seen != hash {
				return AuthorizationApplyResult{}, errors.New("event identity reused with different content")
			}
			continue
		}
		prior := next.Versions[item.GroupID]
		if item.GroupVersion > prior+1 {
			return AuthorizationApplyResult{RequiresSnapshot: true}, nil
		}
		next.Receipts[item.EventID] = hash
		if item.GroupVersion < prior {
			continue
		}
		next.Versions[item.GroupID] = item.GroupVersion
		next.Effects++
		effects++
	}
	if len(next.Receipts) > 100000 || len(next.Versions) > 10000 {
		return AuthorizationApplyResult{}, errors.New("journal capacity exhausted")
	}
	if e := ctx.Err(); e != nil {
		return AuthorizationApplyResult{}, e
	}
	if e := j.persist(next); e != nil {
		return AuthorizationApplyResult{}, e
	}
	j.state = next
	return AuthorizationApplyResult{NewEffects: effects}, nil
}

func (j *FileAuthorizationJournal) ApplySnapshot(ctx context.Context, snapshot AuthorizationSnapshot) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return errors.New("journal closed")
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	if !integrationBound(snapshot.SnapshotID, 512) || snapshot.Groups == nil || len(snapshot.Groups) > 100 {
		return errors.New("invalid bounded snapshot")
	}
	next := cloneAuthorizationState(j.state)
	next.Connected = false
	seen := map[string]bool{}
	subjects := 0
	for _, group := range snapshot.Groups {
		if !integrationBound(group.GroupID, 512) || group.GroupVersion < 0 || group.Subjects == nil || seen[group.GroupID] || group.GroupVersion < next.Versions[group.GroupID] {
			return errors.New("invalid or rolled-back snapshot")
		}
		seen[group.GroupID] = true
		unique := map[string]bool{}
		for _, subject := range group.Subjects {
			subjects++
			if subjects > 2000 || !integrationBound(subject.UserID, 512) || subject.AuthorizationEpoch < 0 || unique[subject.UserID] {
				return errors.New("invalid bounded snapshot subjects")
			}
			unique[subject.UserID] = true
		}
		next.Versions[group.GroupID] = group.GroupVersion
	}
	if len(next.Versions) > 10000 {
		return errors.New("journal group capacity exceeded")
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	if e := j.persist(next); e != nil {
		return e
	}
	j.state = next
	return nil
}
func (j *FileAuthorizationJournal) SetConnected(ctx context.Context, connected bool) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return errors.New("journal closed")
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	next := cloneAuthorizationState(j.state)
	next.Connected = connected
	if e := j.persist(next); e != nil {
		return e
	}
	j.state = next
	return nil
}
func (j *FileAuthorizationJournal) Stats(ctx context.Context) (AuthorizationJournalStats, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return AuthorizationJournalStats{}, errors.New("journal closed")
	}
	if e := ctx.Err(); e != nil {
		return AuthorizationJournalStats{}, e
	}
	return AuthorizationJournalStats{Receipts: len(j.state.Receipts), Effects: j.state.Effects, Connected: j.state.Connected}, nil
}
func (j *FileAuthorizationJournal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return nil
	}
	j.closed = true
	j.state.Connected = false
	e := j.persist(j.state)
	if er := releaseJournalOwnership(j.lock); e == nil {
		e = er
	}
	return e
}

// installJournalGuard atomically creates complete content without replacing a
// legacy owner's O_EXCL lock. A failed/partial prior setup remains fail-closed.
// The guard is deliberately persistent, including after clean close and failure.
func installJournalGuard(path string) (bool, error) {
	const marker = "Aegir journal ownership v2; OS lock required\n"
	if info, e := os.Lstat(path); e == nil {
		if !info.Mode().IsRegular() || info.Size() != int64(len(marker)) {
			return false, errors.New("legacy or invalid journal guard requires stopped operator migration")
		}
		f, e := os.Open(path)
		if e != nil {
			return false, errors.New("journal guard unavailable")
		}
		b, e := io.ReadAll(io.LimitReader(f, int64(len(marker)+1)))
		ce := f.Close()
		if e != nil || ce != nil || !bytes.Equal(b, []byte(marker)) {
			return false, errors.New("legacy or invalid journal guard requires stopped operator migration")
		}
		return true, nil
	} else if !os.IsNotExist(e) {
		return false, errors.New("journal guard unavailable")
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".aegir-guard-*.tmp")
	if e != nil {
		return false, errors.New("guard temporary unavailable")
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write([]byte(marker))
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil || ce != nil {
		return false, errors.New("guard durable write failed")
	}
	if os.Link(name, path) != nil {
		return false, errors.New("guard creation raced or local filesystem unsupported")
	}
	return false, nil
}

func journalEnvelopeShape(m map[string]any) bool {
	if len(m) != 2 || !legacyHas(m, "sha256", "state") {
		return false
	}
	state, ok := m["state"].(map[string]any)
	if !ok || len(state) != 6 || !legacyHas(state, "format", "binding", "connected", "receipts", "versions", "effects") {
		return false
	}
	if _, ok = state["connected"].(bool); !ok {
		return false
	}
	if _, ok = state["binding"].(string); !ok {
		return false
	}
	return true
}

func legacyHas(m map[string]any, names ...string) bool {
	for _, name := range names {
		if _, ok := m[name]; !ok {
			return false
		}
	}
	return true
}
