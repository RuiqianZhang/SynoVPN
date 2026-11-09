package store

import (
	"path/filepath"
	"slices"
	"testing"
)

func TestExistingSchema2DatabaseGainsDurableRouteSettings(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a previous release's v2 database with no settings table.
	if _, err = db.DB.Exec("DROP TABLE settings"); err != nil {
		t.Fatal(err)
	}
	db.DB.Close()
	db, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	routes, err := db.PublicRoutes()
	if err != nil || len(routes) != 0 {
		t.Fatal("missing empty default")
	}
	if err = db.SetPublicRoutes("admin", []string{"8.8.8.8/32"}); err != nil {
		t.Fatal(err)
	}
	db.DB.Close()
	db, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.DB.Close()
	routes, err = db.PublicRoutes()
	if err != nil || !slices.Equal(routes, []string{"8.8.8.8/32"}) {
		t.Fatal("restart lost settings")
	}
	var version int
	if err = db.DB.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != 2 {
		t.Fatal("unexpected schema migration")
	}
}

func TestUserRulesPreserveDenyAllAndInheritanceAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.RememberUser("dsm:1026:alice", "alice"); err != nil {
		t.Fatal(err)
	}
	if err = db.SetUserRoutes("admin", "dsm:1026:alice", []string{}, false); err != nil {
		t.Fatal(err)
	}
	db.DB.Close()
	db, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.DB.Close()
	routes, custom, err := db.UserRoutes("dsm:1026:alice")
	if err != nil || !custom || routes == nil || len(routes) != 0 {
		t.Fatal("deny-all became inherited", routes, custom, err)
	}
	if err = db.SetUserRoutes("admin", "dsm:1026:alice", nil, true); err != nil {
		t.Fatal(err)
	}
	if _, custom, err = db.UserRoutes("dsm:1026:alice"); err != nil || custom {
		t.Fatal("inheritance reset failed")
	}
}
