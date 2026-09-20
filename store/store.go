package store

import (
	"database/sql"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"xcert/log"

	_ "modernc.org/sqlite"
)

const FileName = "xcert.db"

type Store struct {
	db *sql.DB
}

type Record struct {
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

type RevokedEntry struct {
	Serial *big.Int
	Time   time.Time
}

func Open(path string) (*Store, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	dsn := (&url.URL{Scheme: "file", Path: filepath.ToSlash(abs), RawQuery: "_txlock=immediate"}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// A single connection keeps the per-connection PRAGMAs effective and
	// serializes writers inside the process.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec("PRAGMA busy_timeout = 5000"); err != nil {
		db.Close()
		return nil, err
	}
	var journalMode string
	if err := db.QueryRow("PRAGMA journal_mode = WAL").Scan(&journalMode); err != nil {
		db.Close()
		return nil, err
	}
	s := &Store{db: db}
	if err := s.init(); err != nil {
		db.Close()
		return nil, err
	}
	if err := s.importLegacy(filepath.Dir(abs)); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) init() error {
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
	revoked_at TEXT,
	deleted    INTEGER NOT NULL DEFAULT 0
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
	if err := s.ensureColumn("certs", "deleted", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if _, err := s.db.Exec(`UPDATE certs SET revoked_at = created_at WHERE status = 'R' AND (revoked_at IS NULL OR revoked_at = '')`); err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT OR IGNORE INTO meta(key, value) VALUES('serial', '01')`)
	return err
}

func (s *Store) ensureColumn(table, column, typ string) error {
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

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// importLegacy reads the serial and index.txt files of a CA directory created
// by the old xcert.sh script so new certificates continue the old numbering
// and previously issued records are known. The layout is deprecated.
func (s *Store) importLegacy(dir string) error {
	serialPath := filepath.Join(dir, "serial")
	indexPath := filepath.Join(dir, "index.txt")
	if !fileExists(serialPath) && !fileExists(indexPath) {
		return nil
	}
	log.Warn("legacy xcert.sh directory %s is deprecated, reading its serial and index.txt\n", dir)
	if err := s.importLegacySerial(serialPath); err != nil {
		return err
	}
	return s.importLegacyIndex(indexPath)
}

func (s *Store) importLegacySerial(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	n, ok := new(big.Int).SetString(strings.TrimSpace(string(data)), 16)
	if !ok || n.Sign() <= 0 {
		return nil
	}
	var current string
	if err := s.db.QueryRow(`SELECT value FROM meta WHERE key = 'serial'`).Scan(&current); err != nil {
		return err
	}
	cur, ok := new(big.Int).SetString(current, 16)
	if ok && cur.Cmp(n) >= 0 {
		return nil
	}
	_, err = s.db.Exec(`UPDATE meta SET value = ? WHERE key = 'serial'`, fmt.Sprintf("%02x", n))
	return err
}

func (s *Store) importLegacyIndex(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM certs`).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 6 {
			continue
		}
		serial := strings.ToUpper(strings.TrimSpace(fields[3]))
		subject := strings.TrimSpace(fields[5])
		if serial == "" || subject == "" {
			continue
		}
		status := "V"
		var revokedAt any
		if fields[0] == "R" {
			status = "R"
			if t, ok := parseLegacyTime(fields[2]); ok {
				revokedAt = t.UTC().Format(time.RFC3339)
			}
		}
		notAfter := now
		if t, ok := parseLegacyTime(fields[1]); ok {
			notAfter = t.UTC().Format(time.RFC3339)
		}
		if _, err := tx.Exec(
			`INSERT INTO certs(serial, subject, type, name, status, not_before, not_after, cert_path, key_path, created_at, revoked_at)
			 VALUES(?, ?, 'cert', ?, ?, ?, ?, '', '', ?, ?)`,
			serial, subject, legacyCommonName(subject), status, now, notAfter, now, revokedAt,
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func parseLegacyTime(value string) (time.Time, bool) {
	t, err := time.Parse("060102150405Z", strings.TrimSpace(value))
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

func legacyCommonName(subject string) string {
	for _, part := range strings.Split(subject, "/") {
		if strings.HasPrefix(part, "CN=") {
			return strings.TrimPrefix(part, "CN=")
		}
	}
	return subject
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) NextSequentialSerial() (*big.Int, error) {
	return s.metaCounter("serial")
}

func (s *Store) NextCRLNumber() (*big.Int, error) {
	return s.metaCounter("crl")
}

func (s *Store) metaCounter(key string) (*big.Int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var current string
	err = tx.QueryRow(`SELECT value FROM meta WHERE key = ?`, key).Scan(&current)
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
	if _, err := tx.Exec(
		`INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		key, fmt.Sprintf("%02x", next),
	); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return n, nil
}

func (s *Store) Record(serial *big.Int, subject, certType, name, certPath, keyPath string, notBefore, notAfter time.Time) error {
	_, err := s.db.Exec(
		`INSERT INTO certs(serial, subject, type, name, status, not_before, not_after, cert_path, key_path, created_at)
		 VALUES(?, ?, ?, ?, 'V', ?, ?, ?, ?, ?)`,
		strings.ToUpper(fmt.Sprintf("%x", serial)), subject, certType, name,
		notBefore.UTC().Format(time.RFC3339), notAfter.UTC().Format(time.RFC3339),
		certPath, keyPath, time.Now().UTC().Format(time.RFC3339),
	)
	return err
}

const recordColumns = `id, serial, subject, type, name, status, COALESCE(not_before, ''), COALESCE(not_after, ''), COALESCE(cert_path, ''), COALESCE(key_path, ''), created_at, revoked_at`

func scanRecords(rows *sql.Rows) ([]Record, error) {
	defer rows.Close()
	var out []Record
	for rows.Next() {
		var r Record
		if err := rows.Scan(&r.ID, &r.Serial, &r.Subject, &r.Type, &r.Name, &r.Status,
			&r.NotBefore, &r.NotAfter, &r.CertPath, &r.KeyPath, &r.CreatedAt, &r.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) List() ([]Record, error) {
	rows, err := s.db.Query(`SELECT ` + recordColumns + ` FROM certs WHERE deleted = 0 ORDER BY id`)
	if err != nil {
		return nil, err
	}
	return scanRecords(rows)
}

func (s *Store) Find(selector string) ([]Record, error) {
	rows, err := s.db.Query(
		`SELECT `+recordColumns+` FROM certs WHERE deleted = 0 AND (lower(serial) = lower(?) OR name = ?) ORDER BY id`,
		selector, selector,
	)
	if err != nil {
		return nil, err
	}
	return scanRecords(rows)
}

func (s *Store) Resolve(selector string) (Record, error) {
	records, err := s.Find(selector)
	if err != nil {
		return Record{}, err
	}
	switch len(records) {
	case 0:
		return Record{}, fmt.Errorf("no certificate found for %q", selector)
	case 1:
		return records[0], nil
	default:
		return Record{}, fmt.Errorf("%q is ambiguous, use the serial number", selector)
	}
}

func (s *Store) SetStatus(selector, status string) (Record, error) {
	record, err := s.Resolve(selector)
	if err != nil {
		return Record{}, err
	}
	var revokedAt any
	if status == "R" {
		timestamp := time.Now().UTC().Format(time.RFC3339)
		revokedAt = timestamp
		record.RevokedAt = sql.NullString{String: timestamp, Valid: true}
	} else {
		record.RevokedAt = sql.NullString{}
	}
	if _, err := s.db.Exec(`UPDATE certs SET status = ?, revoked_at = ? WHERE id = ?`, status, revokedAt, record.ID); err != nil {
		return Record{}, err
	}
	record.Status = status
	return record, nil
}

func (s *Store) Restore(record Record) error {
	if _, err := s.db.Exec(`UPDATE certs SET status = ?, revoked_at = ? WHERE id = ?`, record.Status, record.RevokedAt, record.ID); err != nil {
		return err
	}
	return nil
}

func (s *Store) Delete(selector string, force bool) (Record, error) {
	record, err := s.Resolve(selector)
	if err != nil {
		return Record{}, err
	}
	if record.Status == "R" {
		if !force {
			return Record{}, fmt.Errorf("%s is revoked; unrevoke it or use --force", selector)
		}
		// Keep a tombstone so the serial stays on the CRL.
		if _, err := s.db.Exec(`UPDATE certs SET deleted = 1 WHERE id = ?`, record.ID); err != nil {
			return Record{}, err
		}
		return record, nil
	}
	if _, err := s.db.Exec(`DELETE FROM certs WHERE id = ?`, record.ID); err != nil {
		return Record{}, err
	}
	return record, nil
}

func parseTimestamp(value sql.NullString) (time.Time, bool) {
	if !value.Valid || value.String == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, value.String)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

func (s *Store) Revoked() ([]RevokedEntry, error) {
	rows, err := s.db.Query(`SELECT serial, revoked_at, created_at FROM certs WHERE status = 'R' AND type = 'cert' ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RevokedEntry
	for rows.Next() {
		var serial string
		var revokedAt, createdAt sql.NullString
		if err := rows.Scan(&serial, &revokedAt, &createdAt); err != nil {
			return nil, err
		}
		n, ok := new(big.Int).SetString(serial, 16)
		if !ok {
			continue
		}
		revocationTime, ok := parseTimestamp(revokedAt)
		if !ok {
			revocationTime, ok = parseTimestamp(createdAt)
		}
		if !ok {
			return nil, fmt.Errorf("revoked certificate %s has no valid revocation time", serial)
		}
		out = append(out, RevokedEntry{Serial: n, Time: revocationTime})
	}
	return out, rows.Err()
}
