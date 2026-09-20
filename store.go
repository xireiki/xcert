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
	created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_certs_serial ON certs(serial);
CREATE INDEX IF NOT EXISTS idx_certs_name ON certs(name);
`)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT OR IGNORE INTO meta(key, value) VALUES('serial', '01')`)
	return err
}

func (s *store) close() error {
	return s.db.Close()
}

func (s *store) nextSerial(useRandom bool) (*big.Int, error) {
	if useRandom {
		return randomSerial()
	}
	var current string
	err := s.db.QueryRow(`SELECT value FROM meta WHERE key = 'serial'`).Scan(&current)
	if err == sql.ErrNoRows {
		current = "01"
	} else if err != nil {
		return nil, err
	}
	n, ok := new(big.Int).SetString(current, 16)
	if !ok {
		n = big.NewInt(1)
	}
	if n.Sign() <= 0 {
		n = big.NewInt(1)
	}
	next := new(big.Int).Add(n, big.NewInt(1))
	if _, err := s.db.Exec(
		`INSERT INTO meta(key, value) VALUES('serial', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		fmt.Sprintf("%02x", next),
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
