package store

import (
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), FileName))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestSequentialSerial(t *testing.T) {
	s := openTestStore(t)
	for want := int64(1); want <= 3; want++ {
		serial, err := s.NextSequentialSerial()
		if err != nil {
			t.Fatal(err)
		}
		if serial.Int64() != want {
			t.Fatalf("expected serial %d, got %s", want, serial)
		}
	}
}

func TestSequentialSerialConcurrent(t *testing.T) {
	s := openTestStore(t)
	const workers = 20
	results := make(chan int64, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			serial, err := s.NextSequentialSerial()
			if err != nil {
				return
			}
			results <- serial.Int64()
		}()
	}
	wg.Wait()
	close(results)

	seen := make(map[int64]bool)
	for serial := range results {
		if seen[serial] {
			t.Fatalf("duplicate serial %d", serial)
		}
		seen[serial] = true
	}
	if len(seen) != workers {
		t.Fatalf("expected %d unique serials, got %d", workers, len(seen))
	}
}

func TestSequentialSerialAcrossConnections(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	const stores, each = 8, 10
	var wg sync.WaitGroup
	errs := make(chan error, stores)
	seen := make(chan int64, stores*each)
	for i := 0; i < stores; i++ {
		s, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		wg.Add(1)
		go func(s *Store) {
			defer wg.Done()
			for j := 0; j < each; j++ {
				serial, err := s.NextSequentialSerial()
				if err != nil {
					errs <- err
					return
				}
				seen <- serial.Int64()
			}
		}(s)
	}
	wg.Wait()
	close(errs)
	close(seen)
	for err := range errs {
		t.Fatal(err)
	}
	counts := make(map[int64]int)
	for serial := range seen {
		counts[serial]++
	}
	if len(counts) != stores*each {
		t.Fatalf("expected %d unique serials, got %d", stores*each, len(counts))
	}
}

func TestRecords(t *testing.T) {
	s := openTestStore(t)
	now := time.Now()
	notAfter := now.Add(24 * time.Hour)
	for _, record := range []struct {
		serial *big.Int
		name   string
	}{
		{big.NewInt(1), "a.test"},
		{big.NewInt(2), "dup.test"},
		{big.NewInt(3), "dup.test"},
	} {
		if err := s.Record(record.serial, "CN="+record.name, "cert", record.name, record.name+".cer", record.name+".key", now, notAfter); err != nil {
			t.Fatal(err)
		}
	}

	records, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 3 {
		t.Fatalf("expected 3 records, got %d", len(records))
	}

	record, err := s.Resolve("1")
	if err != nil {
		t.Fatal(err)
	}
	if record.Name != "a.test" {
		t.Fatalf("unexpected record: %+v", record)
	}

	if _, err := s.Resolve("dup.test"); err == nil {
		t.Fatal("expected ambiguous selector error")
	}

	record, err = s.SetStatus("a.test", "R")
	if err != nil {
		t.Fatal(err)
	}
	if record.Status != "R" {
		t.Fatalf("expected status R, got %s", record.Status)
	}
	revoked, err := s.Revoked()
	if err != nil {
		t.Fatal(err)
	}
	if len(revoked) != 1 || revoked[0].Serial.Int64() != 1 {
		t.Fatalf("unexpected revoked entries: %+v", revoked)
	}

	if _, err := s.Delete("a.test", false); err == nil {
		t.Fatal("expected error deleting a revoked record without --force")
	}
	if _, err := s.Delete("a.test", true); err != nil {
		t.Fatal(err)
	}
	records, err = s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records after delete, got %d", len(records))
	}
	revoked, err = s.Revoked()
	if err != nil {
		t.Fatal(err)
	}
	if len(revoked) != 1 || revoked[0].Serial.Int64() != 1 {
		t.Fatalf("expected the tombstone to stay revoked, got %+v", revoked)
	}
}

func TestLegacyImport(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "serial"), []byte("02\n"), 0644); err != nil {
		t.Fatal(err)
	}
	index := "V\t310919022344Z\t\t00\tunknown\t/C=CN/CN=a.test\n" +
		"R\t310919022344Z\t250101000000Z\t01\tunknown\t/C=CN/CN=b.test\n"
	if err := os.WriteFile(filepath.Join(dir, "index.txt"), []byte(index), 0644); err != nil {
		t.Fatal(err)
	}
	s, err := Open(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	records, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 imported records, got %d", len(records))
	}
	if records[1].Name != "b.test" || records[1].Status != "R" {
		t.Fatalf("unexpected imported record: %+v", records[1])
	}
	revoked, err := s.Revoked()
	if err != nil {
		t.Fatal(err)
	}
	if len(revoked) != 1 || revoked[0].Serial.Int64() != 1 {
		t.Fatalf("expected the revoked entry to be imported, got %+v", revoked)
	}
	serial, err := s.NextSequentialSerial()
	if err != nil {
		t.Fatal(err)
	}
	if serial.Int64() != 2 {
		t.Fatalf("expected the serial counter seeded to 2, got %s", serial)
	}
}
