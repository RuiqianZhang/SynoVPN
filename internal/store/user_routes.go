package store

import (
	"database/sql"
	"encoding/json"
	"sort"
)

type PolicyUser struct {
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

func (s *Store) RememberUser(owner, name string) error {
	_, err := s.DB.Exec("INSERT INTO portal_users(owner,name) VALUES(?,?) ON CONFLICT(owner) DO UPDATE SET name=excluded.name WHERE name!=excluded.name", owner, name)
	return err
}
func (s *Store) PolicyUsers() ([]PolicyUser, error) {
	rows, err := s.DB.Query("SELECT owner,name FROM portal_users UNION SELECT DISTINCT owner,'' FROM devices UNION SELECT owner,'' FROM user_routes")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	users := map[string]PolicyUser{}
	for rows.Next() {
		var u PolicyUser
		if err = rows.Scan(&u.Owner, &u.Name); err != nil {
			return nil, err
		}
		if old, ok := users[u.Owner]; !ok || old.Name == "" {
			users[u.Owner] = u
		}
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	out := []PolicyUser{}
	for _, u := range users {
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Owner < out[j].Owner })
	return out, nil
}
func (s *Store) UserRoutes(owner string) ([]string, bool, error) {
	var raw string
	err := s.DB.QueryRow("SELECT routes FROM user_routes WHERE owner=?", owner).Scan(&raw)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	routes := []string{}
	err = json.Unmarshal([]byte(raw), &routes)
	if routes == nil {
		routes = []string{}
	}
	return routes, true, err
}
func (s *Store) SetUserRoutes(actor, owner string, routes []string, inherit bool) error {
	raw, err := json.Marshal(routes)
	if err != nil {
		return err
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if inherit {
		_, err = tx.Exec("DELETE FROM user_routes WHERE owner=?", owner)
	} else {
		_, err = tx.Exec("INSERT INTO user_routes(owner,routes) VALUES(?,?) ON CONFLICT(owner) DO UPDATE SET routes=excluded.routes", owner, string(raw))
	}
	if err != nil {
		return err
	}
	details, _ := json.Marshal(map[string]any{"owner": owner, "routes": routes, "inherit": inherit})
	if _, err = tx.Exec("INSERT INTO audit(at,actor,action,device) VALUES(unixepoch(),?,'user-routes',?)", actor, string(details)); err != nil {
		return err
	}
	return tx.Commit()
}
