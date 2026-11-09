package store

import (
	"database/sql"
	"encoding/json"
)

func (s *Store) PublicRoutes() ([]string, error) {
	var raw string
	err := s.DB.QueryRow("SELECT value FROM settings WHERE name='public-routes'").Scan(&raw)
	if err == sql.ErrNoRows {
		return []string{}, nil
	}
	if err != nil {
		return nil, err
	}
	var routes []string
	err = json.Unmarshal([]byte(raw), &routes)
	return routes, err
}
func (s *Store) SetPublicRoutes(actor string, routes []string) error {
	raw, err := json.Marshal(routes)
	if err != nil {
		return err
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec("INSERT INTO settings(name,value) VALUES('public-routes',?) ON CONFLICT(name) DO UPDATE SET value=excluded.value", string(raw)); err != nil {
		return err
	}
	if _, err = tx.Exec("INSERT INTO audit(at,actor,action,device) VALUES(unixepoch(),?,'public-routes',?)", actor, string(raw)); err != nil {
		return err
	}
	return tx.Commit()
}
