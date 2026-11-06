package store

import "database/sql"
import "errors"

// Global administration reads metadata only; encrypted keys and certificates
// are not fetched. Owner remains internal; the web DTO emits a display name.
const metadataFields = "id,owner,name,platform,state,created,expires,applied,error,NULL,NULL,serial"

func (s *Store) AllMetadata() ([]Device, error) {
	rows, err := s.DB.Query("SELECT " + metadataFields + " FROM devices WHERE id NOT IN (SELECT device FROM device_archive) ORDER BY created DESC,id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Device{}
	for rows.Next() {
		d, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
func (s *Store) Metadata(id string) (Device, error) {
	d, err := scan(s.DB.QueryRow("SELECT "+metadataFields+" FROM devices WHERE id=? AND id NOT IN (SELECT device FROM device_archive)", id))
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return d, err
}
func (s *Store) AdminRevoke(actor, id string) (string, error) {
	d, err := s.Metadata(id)
	if err != nil {
		return "", err
	}
	// Owner is immutable. Audit actor is the verified administrator, while the
	// retained device row identifies the target owner for the audit join.
	return d.Owner, s.revoke(d.Owner, id, actor, "admin-revoke")
}
