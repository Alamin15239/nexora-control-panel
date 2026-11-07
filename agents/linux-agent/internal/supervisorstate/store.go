package supervisorstate

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"
)

const schemaVersion = 1
const maxStateFileBytes = 4 << 20

var opaqueID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$`)
var containerID = regexp.MustCompile(`^[a-f0-9]{12,64}$`)

// WorkloadState contains only runtime metadata. Secrets, environment values,
// customer payloads and build commands must never be persisted in this file.
type WorkloadState struct {
	WorkloadID  string    `json:"workloadId"`
	ReleaseID   string    `json:"releaseId"`
	ContainerID string    `json:"containerId"`
	State       string    `json:"state"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

type snapshot struct {
	Version   int                     `json:"version"`
	UpdatedAt time.Time               `json:"updatedAt"`
	Workloads map[string]WorkloadState `json:"workloads"`
}

// Store is a single-process durable state store. Its parent directory must be
// owned by the service account and inaccessible to untrusted local users.
type Store struct {
	path string
	mu   sync.Mutex
}

func Open(path string) (*Store, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("state path must be an absolute clean path")
	}
	parent := filepath.Dir(path)
	parentInfo, err := os.Lstat(parent)
	if err != nil {
		return nil, fmt.Errorf("inspect state directory: %w", err)
	}
	if !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 || parentInfo.Mode().Perm()&0077 != 0 {
		return nil, errors.New("state directory must be a real directory not writable by group or others")
	}
	s := &Store{path: path}
	if _, err := s.readLocked(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return s, nil
}

func (s *Store) Load() ([]WorkloadState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.readLocked()
	if err != nil {
		return nil, err
	}
	out := make([]WorkloadState, 0, len(data.Workloads))
	for _, item := range data.Workloads {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].WorkloadID < out[j].WorkloadID })
	return out, nil
}

// Get returns one persisted workload snapshot without exposing the internal map.
func (s *Store) Get(workloadID string) (WorkloadState, bool, error) {
	if !opaqueID.MatchString(workloadID) {
		return WorkloadState{}, false, errors.New("invalid workload identifier")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, err := s.readLocked()
	if err != nil {
		if os.IsNotExist(err) { return WorkloadState{}, false, nil }
		return WorkloadState{}, false, err
	}
	item, ok := current.Workloads[workloadID]
	return item, ok, nil
}

func (s *Store) Upsert(item WorkloadState) error {
	if err := validate(item); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, err := s.readLocked()
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if current.Workloads == nil {
		current = snapshot{Version: schemaVersion, Workloads: make(map[string]WorkloadState)}
	}
	item.UpdatedAt = time.Now().UTC()
	current.Workloads[item.WorkloadID] = item
	current.UpdatedAt = item.UpdatedAt
	return s.writeLocked(current)
}

// UpsertMany validates the entire batch before writing one durable snapshot.
// Duplicate workload IDs in a batch are rejected to avoid order-dependent updates.
func (s *Store) UpsertMany(items []WorkloadState) error {
	if len(items) == 0 { return nil }
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		if err := validate(item); err != nil { return err }
		if _, exists := seen[item.WorkloadID]; exists {
			return errors.New("duplicate workload identifier in state batch")
		}
		seen[item.WorkloadID] = struct{}{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, err := s.readLocked()
	if err != nil && !os.IsNotExist(err) { return err }
	if current.Workloads == nil {
		current = snapshot{Version: schemaVersion, Workloads: make(map[string]WorkloadState)}
	}
	now := time.Now().UTC()
	for _, item := range items {
		item.UpdatedAt = now
		current.Workloads[item.WorkloadID] = item
	}
	current.UpdatedAt = now
	return s.writeLocked(current)
}

func (s *Store) Delete(workloadID string) error {
	if !opaqueID.MatchString(workloadID) {
		return errors.New("invalid workload identifier")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, err := s.readLocked()
	if err != nil {
		if os.IsNotExist(err) { return nil }
		return err
	}
	if _, exists := current.Workloads[workloadID]; !exists {
		return nil
	}
	delete(current.Workloads, workloadID)
	current.UpdatedAt = time.Now().UTC()
	return s.writeLocked(current)
}

func validate(item WorkloadState) error {
	if !opaqueID.MatchString(item.WorkloadID) || !opaqueID.MatchString(item.ReleaseID) ||
		!containerID.MatchString(item.ContainerID) {
		return errors.New("invalid workload, release or container identifier")
	}
	switch item.State {
	case "created", "running", "paused", "exited", "stopped", "dead":
	default:
		return errors.New("unsupported workload state")
	}
	return nil
}

func (s *Store) readLocked() (snapshot, error) {
	var current snapshot
	info, err := os.Lstat(s.path)
	if err != nil { return current, err }
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return current, errors.New("state file must be a regular file with owner-only permissions")
	}
	if info.Size() > maxStateFileBytes {
		return current, errors.New("state file exceeds maximum size")
	}
	raw, err := os.ReadFile(s.path)
	if err != nil { return current, err }
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&current); err != nil {
		return current, fmt.Errorf("decode runtime state: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return current, errors.New("runtime state contains trailing JSON data")
	}
	if current.Version != schemaVersion || current.Workloads == nil || len(current.Workloads) > 100000 {
		return current, errors.New("unsupported or invalid runtime state schema")
	}
	for key, item := range current.Workloads {
		if key != item.WorkloadID {
			return current, errors.New("runtime state workload key mismatch")
		}
		if err := validate(item); err != nil { return current, err }
	}
	return current, nil
}

func (s *Store) writeLocked(current snapshot) error {
	raw, err := json.Marshal(current)
	if err != nil { return err }
	if len(raw) > maxStateFileBytes { return errors.New("runtime state exceeds maximum size") }
	if info, err := os.Lstat(s.path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
			return errors.New("refusing to replace unsafe runtime state file")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil { return fmt.Errorf("generate state temp name: %w", err) }
	tmpPath := s.path + ".tmp-" + hex.EncodeToString(nonce)
	tmp, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil { return fmt.Errorf("create runtime state temp file: %w", err) }
	tmpName := tmp.Name()
	ok := false
	defer func() {
		_ = tmp.Close()
		if !ok { _ = os.Remove(tmpName) }
	}()
	if _, err = tmp.Write(raw); err != nil { return err }
	if err = tmp.Sync(); err != nil { return err }
	if err = tmp.Close(); err != nil { return err }
	if err = os.Rename(tmpName, s.path); err != nil { return err }
	dir, err := os.Open(filepath.Dir(s.path))
	if err != nil { return err }
	err = dir.Sync()
	closeErr := dir.Close()
	if err != nil { return err }
	if closeErr != nil { return closeErr }
	ok = true
	return nil
}
