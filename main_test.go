package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestChain(t *testing.T) {
	ca := filepath.Join(t.TempDir(), "ca")
	exec(t, "root", "-o", ca)
	exec(t, "inte", "-o", ca, "-c", filepath.Join(ca, "RootCA.cer"), "-k", filepath.Join(ca, "RootCA.key"))
	exec(t, "cert", "-D", ca, "-d", "example.com", "-d", "www.example.com")

	roots := x509.NewCertPool()
	inter := x509.NewCertPool()
	addPEM(t, roots, filepath.Join(ca, "RootCA.cer"))
	addPEM(t, inter, filepath.Join(ca, "chain.cer"))

	leafPEM, err := os.ReadFile(filepath.Join(ca, "certs", "example.com_ecc", "example.com.cer"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(leafPEM)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		DNSName:       "www.example.com",
	}); err != nil {
		t.Fatalf("chain verification failed: %v", err)
	}
}

func exec(t *testing.T, args ...string) {
	t.Helper()
	cmd := newRootCommand()
	cmd.SetArgs(args)
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
}

func addPEM(t *testing.T, pool *x509.CertPool, path string) {
	t.Helper()
	pem, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatalf("failed to add %s to pool", path)
	}
}
