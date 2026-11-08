package rollbackoutbox

import (
	"os"
	"path/filepath"
	"testing"
)

func fixture(t *testing.T) (*Store,Operation) {
	t.Helper()
	dir:=t.TempDir()
	if err:=os.Chmod(dir,0700); err!=nil { t.Fatal(err) }
	s,err:=Open(filepath.Join(dir,"outbox.json")); if err!=nil { t.Fatal(err) }
	return s,Operation{ID:"op-rollback-001",FailedDeploymentID:"dep-failed-001",FailedReleaseID:"rel-failed-001",
		TargetDeploymentID:"dep-good-001",TargetReleaseID:"rel-good-001",ProjectID:"project-001",
		OrganizationID:"org-001",NodeID:"node-001",ExpectedActiveReleaseID:"rel-failed-001",
		ArtifactSHA256:"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
}

func TestEnqueueIsDurableAndIdempotent(t *testing.T) {
	s,op:=fixture(t)
	first,err:=s.Enqueue(op); if err!=nil {t.Fatal(err)}
	second,err:=s.Enqueue(op); if err!=nil {t.Fatal(err)}
	if first.ID!=second.ID || first.State!="pending" {t.Fatalf("unexpected retry result: %#v",second)}
	items,err:=s.List(); if err!=nil {t.Fatal(err)}
	if len(items)!=1 {t.Fatalf("expected one durable operation, got %d",len(items))}
}

func TestEnqueueRejectsConflictingOperationID(t *testing.T) {
	s,op:=fixture(t)
	if _,err:=s.Enqueue(op); err!=nil {t.Fatal(err)}
	op.TargetReleaseID="rel-other-001"
	if _,err:=s.Enqueue(op); err==nil {t.Fatal("conflicting operation ID accepted")}
}

func TestTransitionsRequireVerifiedProbeAndOrderedStates(t *testing.T) {
	s,op:=fixture(t)
	if _,err:=s.Enqueue(op); err!=nil {t.Fatal(err)}
	if _,err:=s.Transition(op.ID,"verified","",200,12); err==nil {t.Fatal("skipped switch state")}
	if _,err:=s.Transition(op.ID,"switched","",0,0); err!=nil {t.Fatal(err)}
	if _,err:=s.Transition(op.ID,"verified","",503,12); err==nil {t.Fatal("non-success probe marked verified")}
	if _,err:=s.Transition(op.ID,"verified","",200,12); err!=nil {t.Fatal(err)}
	if _,err:=s.Transition(op.ID,"reported","",0,0); err!=nil {t.Fatal(err)}
	if _,err:=s.Transition(op.ID,"blocked","network",0,0); err==nil {t.Fatal("terminal reported operation changed")}
}

func TestBlockedOperationRequiresReason(t *testing.T) {
	s,op:=fixture(t)
	if _,err:=s.Enqueue(op); err!=nil {t.Fatal(err)}
	if _,err:=s.Transition(op.ID,"blocked","",0,0); err==nil {t.Fatal("blocked without reason accepted")}
}

func TestRejectsUnsafeOutboxFile(t *testing.T) {
	s,op:=fixture(t)
	if _,err:=s.Enqueue(op); err!=nil {t.Fatal(err)}
	if err:=os.Chmod(s.path,0660); err!=nil {t.Fatal(err)}
	if _,err:=s.List(); err==nil {t.Fatal("group-readable outbox accepted")}
}

func TestRejectsSymlinkOutbox(t *testing.T) {
	dir:=t.TempDir()
	if err:=os.Chmod(dir,0700); err!=nil {t.Fatal(err)}
	target:=filepath.Join(dir,"target")
	if err:=os.WriteFile(target,[]byte("{}"),0600); err!=nil {t.Fatal(err)}
	path:=filepath.Join(dir,"outbox.json")
	if err:=os.Symlink(target,path); err!=nil {t.Fatal(err)}
	if _,err:=Open(path); err==nil {t.Fatal("symlink outbox accepted")}
}

func TestRejectsInconsistentReleaseTransition(t *testing.T) {
	s,op:=fixture(t)
	op.ExpectedActiveReleaseID="rel-not-failed-001"
	if _,err:=s.Enqueue(op); err==nil {t.Fatal("inconsistent expected active release accepted")}
}
