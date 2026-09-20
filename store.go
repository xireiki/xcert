package main

import (
	"database/sql"
	"fmt"
	"math/big"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const dbFileName = "xcert.db"

type store struct {
	db *sql.DB
}

type certRecord struct {
	ID        int64
	Serial    string
	Subject   string
	Type      string
	Name      string
	Status    string
	NotBefore string
	NotAfter  string
	CertPath  string
	KeyPath   string
	CreatedAt string
	RevokedAt sql.NullString
}

type revokedEntry struct {
	Serial *big.Int
	Time   time.Time
}

func openStore(path string) (*store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	s := &store{db: db}
	if err := s.init(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *store) init() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS meta (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS certs (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	serial     TEXT NOT NULL,
	subject    TEXT NOT NULL,
	type       TEXT NOT NULL,
	name       TEXT,
	status     TEXT NOT NULL DEFAULT 'V',
	not_before TEXT NOT NULL,
	not_after  TEXT NOT NULL,
	cert_path  TEXT,
	key_path   TEXT,
	created_at TEXT NOT NULL,
	revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_certs_serial ON certs(serial);
CREATE INDEX IF NOT EXISTS idx_certs_name ON certs(name);
`)
	if err != nil {
		return err
	}
	if err := s.ensureColumn("certs", "revoked_at", "TEXT"); err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT OR IGNORE INTO meta(key, value) VALUES('serial', '01')`)
	return err
}

func (s *store) ensureColumn(table, column, typ string) error {
	rows, err := s.db.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return err
		}
		if name == column {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	_, err = s.db.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, typ))
	return err
}

func (s *store) close() error {
	return s.db.Close()
}

func (s *store) nextSerial(sequential bool) (*big.Int, error) {
	if !sequential {
		return randomSerial()
	}
	current, err := s.metaCounter("serial")
	if err != nil {
		return nil, err
	}
	return current, nil
}

func (s *store) nextCRLNumber() (*big.Int, error) {
	return s.metaCounter("crl")
}

func (s *store) metaCounter(key string) (*big.Int, error) {
	var current string
	err := s.db.QueryRow(`SELECT value FROM meta WHERE key = ?`, key).Scan(&current)
	if err == sql.ErrNoRows {
		current = "01"
	} else if err != nil {
		return nil, err
	}
	n, ok := new(big.Int).SetString(current, 16)
	if !ok || n.Sign() <= 0 {
		n = big.NewInt(1)
	}
	next := new(big.Int).Add(n, big.NewInt(1))
	if _, err := s.db.Exec(
		`INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		key, fmt.Sprintf("%02x", next),
	); err != nil {
		return nil, err
	}
	return n, nil
}

func (s *store) record(serial *big.Int, subject, certType, name, certPath, keyPath string, notBefore, notAfter time.Time) error {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO certs(serial, subject, type, name, status, not_before, not_after, cert_path, key_path, created_at)
		 VALUES(?, ?, ?, ?, 'V', ?, ?, ?, ?, ?)`,
		strings.ToUpper(fmt.Sprintf("%x", serial)), subject, certType, name,
		notBefore.UTC().Format(time.RFC3339), notAfter.UTC().Format(time.RFC3339),
		certPath, keyPath, time.Now().UTC().Format(time.RFC3339),
	)
	return err
}

const recordColumns = `id, serial, subject, type, name, status, COALESCE(not_before, ''), COALESCE(not_after, ''), COALESCE(cert_path, ''), COALESCE(key_path, ''), created_at, revoked_at`

func scanRecords(rows *sql.Rows) ([]certRecord, error) {
	defer rows.Close()
	var out []certRecord
	for rows.Next() {
		var r certRecord
		if err := rows.Scan(&r.ID, &r.Serial, &r.Subject, &r.Type, &r.Name, &r.Status,
			&r.NotBefore, &r.NotAfter, &r.CertPath, &r.KeyPath, &r.CreatedAt, &r.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *store) list() ([]certRecord, error) {
	rows, err := s.db.Query(`SELECT ` + recordColumns + ` FROM certs ORDER BY id`)
	if err != nil {
		return nil, err
	}
	return scanRecords(rows)
}

func (s *store) find(selector string) ([]certRecord, error) {
	rows, err := s.db.Query(
		`SELECT `+recordColumns+` FROM certs WHERE lower(serial) = lower(?) OR name = ? ORDER BY id`,
		selector, selector,
	)
	if err != nil {
		return nil, err
	}
	return scanRecords(rows)
}

func (s *store) resolve(selector string) (certRecord, error) {
	recs, err := s.find(selector)
	if err != nil {
		return certRecord{}, err
	}
	switch len(recs) {
	case 0:
		return certRecord{}, fmt.Errorf("no certificate found for %q", selector)
	case 1:
		return recs[0], nil
	default:
		return certRecord{}, fmt.Errorf("%q is ambiguous, use the serial number", selector)
	}
}

func (s *store) setStatus(selector, status string) (certRecord, error) {
	rec, err := s.resolve(selector)
	if err != nil {
		return certRecord{}, err
	}
	var revokedAt any
	if status == "R" {
		revokedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if _, err := s.db.Exec(`UPDATE certs SET status = ?, revoked_at = ? WHERE id = ?`, status, revokedAt, rec.ID); err != nil {
		return certRecord{}, err
	}
	rec.Status = status
	return rec, nil
}

func (s *store) delete(selector string) (certRecord, error) {
	rec, err := s.resolve(selector)
	if err != nil {
		return certRecord{}, err
	}
	if _, err := s.db.Exec(`DELETE FROM certs WHERE id = ?`, rec.ID); err != nil {
		return certRecord{}, err
	}
	return rec, nil
}

func (s *store) revoked() ([]revokedEntry, error) {
	rows, err := s.db.Query(`SELECT serial, revoked_at FROM certs WHERE status = 'R' ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []revokedEntry
	for rows.Next() {
		var serial string
		var revokedAt sql.NullString
		if err := rows.Scan(&serial, &revokedAt); err != nil {
			return nil, err
		}
		n, ok := new(big.Int).SetString(serial, 16)
		if !ok {
			continue
		}
		entry := revokedEntry{Serial: n, Time: time.Now()}
		if revokedAt.Valid {
			if t, err := time.Parse(time.RFC3339, revokedAt.String); err == nil {
				entry.Time = t
			}
		}
		out = append(out, entry)
	}
	return out, rows.Err()
}
