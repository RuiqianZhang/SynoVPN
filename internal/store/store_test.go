package store

import (
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestQuotaRemainsCorrectWithConcurrentRequests(t *testing.T) {
	s, e := Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			d := Device{ID: string(rune('a' + i)), Owner: "user", Name: "device", Platform: "ios", Created: time.Now().Unix(), Expires: time.Now().Add(time.Hour).Unix(), PrivateKey: []byte("encrypted")}
			e := s.Create(d, 2)
			if e == nil {
				accepted.Add(1)
			} else if !errors.Is(e, ErrQuota) {
				t.Errorf("unexpected create failure: %v", e)
			}
		}(i)
	}
	wg.Wait()
	if accepted.Load() != 2 {
		t.Fatalf("quota race: accepted %d", accepted.Load())
	}
}
func TestV1MigrationDisablesPasswordProfiles(t *testing.T) {
	dir := t.TempDir()
	old, e := sql.Open("sqlite", filepath.Join(dir, "synovpn.db"))
	if e != nil {
		t.Fatal(e)
	}
	_, e = old.Exec(`CREATE TABLE devices(id TEXT PRIMARY KEY,owner TEXT NOT NULL,name TEXT NOT NULL,platform TEXT NOT NULL,state TEXT NOT NULL,created INTEGER NOT NULL,expires INTEGER NOT NULL,applied INTEGER NOT NULL DEFAULT 0,error TEXT NOT NULL DEFAULT '',secret BLOB);CREATE TABLE audit(id INTEGER PRIMARY KEY,at INTEGER,actor TEXT,action TEXT,device TEXT);INSERT INTO devices VALUES('aaaaaaaaaaaaaaaaaaaaaa','alice','old','windows','active',1,9999999999,1,'',X'010203');PRAGMA user_version=1;`)
	if e != nil {
		t.Fatal(e)
	}
	old.Close()
	s, e := Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	d, e := s.Get("alice", "aaaaaaaaaaaaaaaaaaaaaa")
	if e != nil {
		t.Fatal(e)
	}
	if d.State != "revoking" || d.Applied || len(d.PrivateKey) != 0 || len(d.Certificate) != 0 {
		t.Fatal("legacy password configuration remained usable")
	}
	var version int
	s.DB.QueryRow("PRAGMA user_version").Scan(&version)
	if version != 2 {
		t.Fatal("migration version not committed")
	}
}
func TestRevocationIntentSurvivesReopeningDatabase(t *testing.T) {
	dir := t.TempDir()
	s, e := Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	d := Device{ID: "one", Owner: "alice", Name: "phone", Platform: "ios", Created: 1, Expires: 2, PrivateKey: []byte("ciphertext")}
	if e = s.Create(d, 5); e != nil {
		t.Fatal(e)
	}
	if e = s.Revoke("alice", d.ID); e != nil {
		t.Fatal(e)
	}
	s.DB.Close()
	s, e = Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	got, e := s.Get("alice", d.ID)
	if e != nil {
		t.Fatal(e)
	}
	if got.State != "revoking" || got.Applied || len(got.PrivateKey) == 0 {
		t.Fatal("pending revocation lost on restart")
	}
}

func TestArchivePersistsAndRetainsOwnerAudit(t *testing.T) {
	dir := t.TempDir()
	s, e := Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	d := Device{ID: "archived", Owner: "user", Name: "old", Platform: "ios", Expires: time.Now().Add(time.Hour).Unix()}
	if e = s.Create(d, 5); e != nil {
		t.Fatal(e)
	}
	s.Revoke("user", d.ID)
	s.FinishRevoke(d.ID)
	if e = s.Archive("user", d.ID, "manager", true); e != nil {
		t.Fatal(e)
	}
	s.DB.Close()
	s, e = Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	rows, e := s.List("user")
	if e != nil || len(rows) != 0 {
		t.Fatal("archive not persisted")
	}
	var owner string
	if e = s.DB.QueryRow("SELECT d.owner FROM audit a JOIN devices d ON a.device=d.id WHERE a.action='admin-delete-record' AND a.actor='manager'").Scan(&owner); e != nil || owner != "user" {
		t.Fatal("owner audit lost")
	}
}
