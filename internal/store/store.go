package store

import (
	"database/sql"
	"errors"
	_ "modernc.org/sqlite"
	"os"
	"path/filepath"
	"time"
)

type Device struct {
	ID          string `json:"id"`
	Owner       string `json:"-"`
	Name        string `json:"name"`
	Platform    string `json:"platform"`
	State       string `json:"state"`
	Created     int64  `json:"created"`
	Expires     int64  `json:"expires"`
	Applied     bool   `json:"applied"`
	Online      bool   `json:"online"`
	Error       string `json:"error,omitempty"`
	PrivateKey  []byte `json:"-"`
	Certificate []byte `json:"-"`
	Serial      string `json:"serial,omitempty"`
}
type Store struct{ DB *sql.DB }

var ErrQuota = errors.New("device quota reached")
var ErrNotFound = errors.New("device not found")

func Open(dir string) (*Store, error) {
	if e := os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}
	path := filepath.Join(dir, "synovpn.db")
	f, e := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	f.Close()
	db, e := sql.Open("sqlite", path)
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	_, e = db.Exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;`)
	if e != nil {
		db.Close()
		return nil, e
	}
	var version int
	if e = db.QueryRow("PRAGMA user_version").Scan(&version); e != nil {
		db.Close()
		return nil, e
	}
	if version > 2 {
		db.Close()
		return nil, errors.New("database is newer than this application")
	}
	tx, e := db.Begin()
	if e != nil {
		db.Close()
		return nil, e
	}
	if version == 0 {
		_, e = tx.Exec(`CREATE TABLE devices(id TEXT PRIMARY KEY,owner TEXT NOT NULL,name TEXT NOT NULL,platform TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('active','revoking','revoked')),created INTEGER NOT NULL,expires INTEGER NOT NULL,applied INTEGER NOT NULL DEFAULT 0,error TEXT NOT NULL DEFAULT '',private_key BLOB,certificate BLOB,serial TEXT NOT NULL DEFAULT '');
 CREATE INDEX device_owner ON devices(owner);
 CREATE TABLE audit(id INTEGER PRIMARY KEY,at INTEGER NOT NULL,actor TEXT NOT NULL,action TEXT NOT NULL,device TEXT NOT NULL);`)
	} else if version == 1 {
		_, e = tx.Exec(`ALTER TABLE devices RENAME COLUMN secret TO private_key;
 ALTER TABLE devices ADD COLUMN certificate BLOB;
 ALTER TABLE devices ADD COLUMN serial TEXT NOT NULL DEFAULT '';
 UPDATE devices SET state='revoking',applied=0,private_key=NULL,error='旧版口令配置已停用，请重新创建设备证书' WHERE state!='revoked';`)
	}
	if e == nil {
		_, e = tx.Exec("CREATE TABLE IF NOT EXISTS settings (name TEXT PRIMARY KEY, value TEXT NOT NULL); CREATE TABLE IF NOT EXISTS user_routes(owner TEXT PRIMARY KEY,routes TEXT NOT NULL); CREATE TABLE IF NOT EXISTS portal_users(owner TEXT PRIMARY KEY,name TEXT NOT NULL)")
	}
	if e == nil {
		_, e = tx.Exec("PRAGMA user_version=2")
	}
	if e != nil {
		tx.Rollback()
		db.Close()
		return nil, e
	}
	if e = tx.Commit(); e != nil {
		db.Close()
		return nil, e
	}
	return &Store{db}, nil
}

const fields = "id,owner,name,platform,state,created,expires,applied,error,private_key,certificate,serial"

type scanner interface{ Scan(...any) error }

func scan(s scanner) (Device, error) {
	var d Device
	e := s.Scan(&d.ID, &d.Owner, &d.Name, &d.Platform, &d.State, &d.Created, &d.Expires, &d.Applied, &d.Error, &d.PrivateKey, &d.Certificate, &d.Serial)
	return d, e
}
func (s *Store) List(owner string) ([]Device, error) {
	q := "SELECT " + fields + " FROM devices"
	args := []any{}
	if owner != "" {
		q += " WHERE owner=?"
		args = append(args, owner)
	}
	q += " ORDER BY created DESC,id"
	rows, e := s.DB.Query(q, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Device{}
	for rows.Next() {
		d, e := scan(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
func (s *Store) Get(owner, id string) (Device, error) {
	d, e := scan(s.DB.QueryRow("SELECT "+fields+" FROM devices WHERE owner=? AND id=?", owner, id))
	if errors.Is(e, sql.ErrNoRows) {
		e = ErrNotFound
	}
	return d, e
}
func (s *Store) Create(d Device, max int) error {
	tx, e := s.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var n int
	e = tx.QueryRow("SELECT count(*) FROM devices WHERE owner=? AND state!='revoked'", d.Owner).Scan(&n)
	if e != nil {
		return e
	}
	if n >= max {
		return ErrQuota
	}
	_, e = tx.Exec("INSERT INTO devices(id,owner,name,platform,state,created,expires,private_key,certificate,serial) VALUES(?,?,?,?,?,?,?,?,?,?)", d.ID, d.Owner, d.Name, d.Platform, "active", d.Created, d.Expires, d.PrivateKey, d.Certificate, d.Serial)
	if e != nil {
		return e
	}
	_, e = tx.Exec("INSERT INTO audit(at,actor,action,device) VALUES(?,?,?,?)", time.Now().Unix(), d.Owner, "create", d.ID)
	if e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) Revoke(owner, id string) error {
	return s.revoke(owner, id, owner, "revoke")
}
func (s *Store) revoke(owner, id, actor, action string) error {
	tx, e := s.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	res, e := tx.Exec("UPDATE devices SET state='revoking',applied=0,error='' WHERE id=? AND owner=? AND state='active'", id, owner)
	if e != nil {
		return e
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		var state string
		if e = tx.QueryRow("SELECT state FROM devices WHERE owner=? AND id=?", owner, id).Scan(&state); e != nil {
			return ErrNotFound
		}
		if action != "admin-revoke" {
			return nil
		}
	}
	_, e = tx.Exec("INSERT INTO audit(at,actor,action,device) VALUES(?,?,?,?)", time.Now().Unix(), actor, action, id)
	if e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) Expire() error {
	_, e := s.DB.Exec("UPDATE devices SET state='revoking',applied=0 WHERE state='active' AND expires<=?", time.Now().Unix())
	return e
}
func (s *Store) Mark(id string, applied bool, msg string) error {
	_, e := s.DB.Exec("UPDATE devices SET applied=?,error=? WHERE id=?", applied, msg, id)
	return e
}
func (s *Store) FinishRevoke(id string) error {
	_, e := s.DB.Exec("UPDATE devices SET state='revoked',applied=1,error='',private_key=NULL WHERE id=? AND state='revoking'", id)
	return e
}
func (s *Store) Audit(owner, action, id string) error {
	_, e := s.DB.Exec("INSERT INTO audit(at,actor,action,device) VALUES(?,?,?,?)", time.Now().Unix(), owner, action, id)
	return e
}

func (s *Store) SetCertificate(id string, cert []byte, serial string) error {
	res, e := s.DB.Exec("UPDATE devices SET certificate=?,serial=? WHERE id=? AND state='active'", cert, serial, id)
	if e != nil {
		return e
	}
	n, e := res.RowsAffected()
	if e != nil {
		return e
	}
	if n != 1 {
		return ErrNotFound
	}
	return nil
}
