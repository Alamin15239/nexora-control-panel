// Package rollbackoutbox persists rollback intent and progress before network
// acknowledgement. It deliberately does not execute rollback or trust API input.
package rollbackoutbox

import (
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
	"syscall"
	"time"
)

const (
	schemaVersion = 1
	maxFileBytes = 1 << 20
	maxOperations = 256
)

var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$`)
var digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Operation struct {
	ID string `json:"id"`
	FailedDeploymentID string `json:"failedDeploymentId"`
	FailedReleaseID string `json:"failedReleaseId"`
	TargetDeploymentID string `json:"targetDeploymentId"`
	TargetReleaseID string `json:"targetReleaseId"`
	ProjectID string `json:"projectId"`
	OrganizationID string `json:"organizationId"`
	NodeID string `json:"nodeId"`
	ExpectedActiveReleaseID string `json:"expectedActiveReleaseId"`
	ArtifactSHA256 string `json:"artifactSha256"`
	State string `json:"state"`
	FailureCode string `json:"failureCode,omitempty"`
	HTTPStatus int `json:"httpStatus,omitempty"`
	ProbeDurationMS int64 `json:"probeDurationMs,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type snapshot struct {
	Version int `json:"version"`
	Operations map[string]Operation `json:"operations"`
}

type Store struct {
	path string
	mu sync.Mutex
}

// Open requires an existing private directory and rejects symlinked state files.
func Open(path string) (*Store, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("outbox path must be absolute and clean")
	}
	info, err := os.Lstat(filepath.Dir(path))
	if err != nil { return nil, fmt.Errorf("inspect outbox directory: %w", err) }
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("outbox directory must be real and owner-only")
	}
	s := &Store{path:path}
	if _, err := s.read(); err != nil && !os.IsNotExist(err) { return nil, err }
	return s,nil
}

// Enqueue creates immutable rollback intent. Reusing an operation ID with a
// different payload is rejected; identical retries return the existing record.
func (s *Store) Enqueue(op Operation) (Operation,error) {
	if err:=validate(op); err!=nil { return Operation{},err }
	s.mu.Lock(); defer s.mu.Unlock()
	unlock, lockErr := s.acquireLock()
	if lockErr != nil { return Operation{}, lockErr }
	defer unlock()
	state,err:=s.read()
	if err!=nil && !os.IsNotExist(err) { return Operation{},err }
	if state.Operations==nil { state=snapshot{Version:schemaVersion,Operations:map[string]Operation{}} }
	if existing,ok:=state.Operations[op.ID]; ok {
		op.State="pending"
		op.CreatedAt=existing.CreatedAt
		op.UpdatedAt=existing.UpdatedAt
		if !sameIntent(existing,op) { return Operation{},errors.New("operation ID conflicts with existing rollback intent") }
		return existing,nil
	}
	if len(state.Operations)>=maxOperations { return Operation{},errors.New("rollback outbox is full") }
	now:=time.Now().UTC()
	op.State="pending"; op.CreatedAt=now; op.UpdatedAt=now
	state.Operations[op.ID]=op
	if err:=s.write(state); err!=nil { return Operation{},err }
	return op,nil
}

// Transition advances one operation through pending -> switched -> verified
// -> reported. blocked is terminal and never represents successful rollback.
func (s *Store) Transition(id,next,failureCode string,httpStatus int,durationMS int64) (Operation,error) {
	if !idPattern.MatchString(id) { return Operation{},errors.New("invalid rollback operation ID") }
	s.mu.Lock(); defer s.mu.Unlock()
	unlock, lockErr := s.acquireLock()
	if lockErr != nil { return Operation{}, lockErr }
	defer unlock()
	state,err:=s.read()
	if err!=nil { return Operation{},err }
	op,ok:=state.Operations[id]
	if !ok { return Operation{},errors.New("rollback operation not found") }
	allowed:=map[string]map[string]bool{
		"pending":{"switched":true,"blocked":true},
		"switched":{"verified":true,"blocked":true},
		"verified":{"reported":true,"blocked":true},
	}
	if op.State==next { return op,nil }
	if !allowed[op.State][next] { return Operation{},errors.New("invalid rollback operation state transition") }
	if next=="verified" && (httpStatus<200 || httpStatus>299 || failureCode!="" || durationMS<0 || durationMS>30000) {
		return Operation{},errors.New("verified rollback requires successful bounded HTTP probe")
	}
	if next=="blocked" {
		if failureCode=="" || len(failureCode)>64 { return Operation{},errors.New("blocked rollback requires bounded failure code") }
	}
	op.State=next; op.FailureCode=failureCode; op.HTTPStatus=httpStatus; op.ProbeDurationMS=durationMS
	op.UpdatedAt=time.Now().UTC()
	state.Operations[id]=op
	if err:=s.write(state); err!=nil { return Operation{},err }
	return op,nil
}

func (s *Store) List() ([]Operation,error) {
	s.mu.Lock(); defer s.mu.Unlock()
	unlock, lockErr := s.acquireLock()
	if lockErr != nil { return nil, lockErr }
	defer unlock()
	state,err:=s.read()
	if os.IsNotExist(err) { return []Operation{},nil }
	if err!=nil { return nil,err }
	out:=make([]Operation,0,len(state.Operations))
	for _,op:=range state.Operations { out=append(out,op) }
	sort.Slice(out,func(i,j int)bool{return out[i].CreatedAt.Before(out[j].CreatedAt)})
	return out,nil
}


// acquireLock serializes mutations across Store instances and processes. The
// private parent directory prevents untrusted users from replacing this file.
func (s *Store) acquireLock() (func(), error) {
	lockPath := s.path + ".lock"
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil { return nil, fmt.Errorf("open rollback outbox lock: %w", err) }
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		_ = file.Close()
		return nil, errors.New("rollback outbox lock must be a private regular file")
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lock rollback outbox: %w", err)
	}
	return func() {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
	}, nil
}

func validate(op Operation) error {
	for _,v:=range []string{op.ID,op.FailedDeploymentID,op.FailedReleaseID,op.TargetDeploymentID,op.TargetReleaseID,op.ProjectID,op.OrganizationID,op.NodeID,op.ExpectedActiveReleaseID} {
		if !idPattern.MatchString(v) { return errors.New("rollback intent contains invalid identifier") }
	}
	if op.FailedReleaseID==op.TargetReleaseID || op.ExpectedActiveReleaseID!=op.FailedReleaseID {
		return errors.New("rollback intent has inconsistent release transition")
	}
	if !digestPattern.MatchString(op.ArtifactSHA256) { return errors.New("rollback intent artifact digest is invalid") }
	return nil
}

func sameIntent(a,b Operation) bool {
	return a.ID==b.ID && a.FailedDeploymentID==b.FailedDeploymentID && a.FailedReleaseID==b.FailedReleaseID &&
		a.TargetDeploymentID==b.TargetDeploymentID && a.TargetReleaseID==b.TargetReleaseID &&
		a.ProjectID==b.ProjectID && a.OrganizationID==b.OrganizationID && a.NodeID==b.NodeID &&
		a.ExpectedActiveReleaseID==b.ExpectedActiveReleaseID && a.ArtifactSHA256==b.ArtifactSHA256
}

func (s *Store) read() (snapshot,error) {
	var state snapshot
	info,err:=os.Lstat(s.path)
	if err!=nil { return state,err }
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink!=0 || info.Mode().Perm()&0077!=0 {
		return state,errors.New("outbox file must be regular and owner-only")
	}
	if info.Size()>maxFileBytes { return state,errors.New("outbox exceeds maximum size") }
	f,err:=os.OpenFile(s.path,os.O_RDONLY|syscall.O_NOFOLLOW,0)
	if err!=nil { return state,err }
	defer f.Close()
	dec:=json.NewDecoder(io.LimitReader(f,maxFileBytes+1)); dec.DisallowUnknownFields()
	if err:=dec.Decode(&state); err!=nil { return state,fmt.Errorf("decode rollback outbox: %w",err) }
	var extra any
	if err:=dec.Decode(&extra); err!=io.EOF { return state,errors.New("rollback outbox has trailing data") }
	if state.Version!=schemaVersion || state.Operations==nil || len(state.Operations)>maxOperations {
		return state,errors.New("unsupported or invalid rollback outbox schema")
	}
	for id,op:=range state.Operations {
		if id!=op.ID { return state,errors.New("rollback outbox key mismatch") }
		if err:=validate(op); err!=nil { return state,err }
		switch op.State { case "pending","switched","verified","reported","blocked": default: return state,errors.New("unsupported rollback outbox state") }
	}
	return state,nil
}

func (s *Store) write(state snapshot) error {
	raw,err:=json.Marshal(state); if err!=nil{return err}
	if len(raw)>maxFileBytes { return errors.New("rollback outbox exceeds maximum size") }
	if info,err:=os.Lstat(s.path); err==nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink!=0 || info.Mode().Perm()&0077!=0 {
			return errors.New("refusing to replace unsafe rollback outbox")
		}
	} else if !os.IsNotExist(err) { return err }
	var nonce [12]byte
	if _,err:=rand.Read(nonce[:]); err!=nil{return err}
	tmp:=s.path+".tmp-"+hex.EncodeToString(nonce[:])
	f,err:=os.OpenFile(tmp,os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW,0600)
	if err!=nil{return err}
	ok:=false
	defer func(){ _=f.Close(); if !ok {_=os.Remove(tmp)} }()
	if _,err=f.Write(raw); err!=nil{return err}
	if err=f.Sync(); err!=nil{return err}
	if err=f.Close(); err!=nil{return err}
	if err=os.Rename(tmp,s.path); err!=nil{return err}
	dir,err:=os.Open(filepath.Dir(s.path)); if err!=nil{return err}
	err=dir.Sync(); closeErr:=dir.Close()
	if err!=nil{return err}; if closeErr!=nil{return closeErr}
	ok=true
	return nil
}

