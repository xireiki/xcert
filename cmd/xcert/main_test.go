package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"xcert/store"
)

func TestChain(t *testing.T) {
	ca := filepath.Join(t.TempDir(), "ca")
	exec(t, "root", "-D", ca)
	exec(t, "inte", "-D", ca, "-c", filepath.Join(ca, "RootCA.cer"), "-k", filepath.Join(ca, "RootCA.key"))
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

	if len(leaf.DNSNames) != 2 {
		t.Fatalf("expected 2 SANs, got %v", leaf.DNSNames)
	}
	if leaf.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Fatalf("expected ECDSA leaf key usage digitalSignature, got %v", leaf.KeyUsage)
	}
	if leaf.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		t.Fatalf("expected ECDSAWithSHA256 leaf signature, got %v", leaf.SignatureAlgorithm)
	}
	if leaf.SerialNumber.BitLen() <= 64 {
		t.Fatalf("expected random serial with more than 64 bits, got %s", leaf.SerialNumber)
	}

	inteBlock, _ := pem.Decode(mustRead(t, filepath.Join(ca, "InteCA.cer")))
	inte, err := x509.ParseCertificate(inteBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.NotAfter.After(inte.NotAfter) {
		t.Fatalf("leaf NotAfter %s exceeds issuer NotAfter %s", leaf.NotAfter, inte.NotAfter)
	}

	st, err := store.Open(filepath.Join(ca, store.FileName))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	records, err := st.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 3 {
		t.Fatalf("expected 3 certs recorded, got %d", len(records))
	}
}

func TestSignCSR(t *testing.T) {
	ca := filepath.Join(t.TempDir(), "ca")
	exec(t, "root", "-D", ca)
	exec(t, "inte", "-D", ca, "-c", filepath.Join(ca, "RootCA.cer"), "-k", filepath.Join(ca, "RootCA.key"))

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "csr.test"},
		DNSNames: []string{"csr.test", "alt.csr.test"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPath := filepath.Join(t.TempDir(), "req.csr")
	if err := os.WriteFile(csrPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), 0644); err != nil {
		t.Fatal(err)
	}

	exec(t, "cert", "-D", ca, "--csr", csrPath)

	dir := filepath.Join(ca, "certs", "csr.test_ecc")
	block, _ := pem.Decode(mustRead(t, filepath.Join(dir, "csr.test.cer")))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !cert.PublicKey.(*ecdsa.PublicKey).Equal(key.Public()) {
		t.Fatal("issued certificate public key does not match the request")
	}
	if len(cert.DNSNames) != 2 {
		t.Fatalf("expected 2 SANs from the request, got %v", cert.DNSNames)
	}
	if _, err := os.Stat(filepath.Join(dir, "csr.test.key")); !os.IsNotExist(err) {
		t.Fatal("expected no private key file when signing an external request")
	}
}

func TestSequentialSerial(t *testing.T) {
	ca := filepath.Join(t.TempDir(), "ca")
	exec(t, "root", "-D", ca)
	exec(t, "inte", "-D", ca, "-c", filepath.Join(ca, "RootCA.cer"), "-k", filepath.Join(ca, "RootCA.key"))
	exec(t, "cert", "-D", ca, "-d", "one.test", "--sequential-serial")
	exec(t, "cert", "-D", ca, "-d", "two.test", "--sequential-serial")

	for name, want := range map[string]int64{"one.test": 1, "two.test": 2} {
		block, _ := pem.Decode(mustRead(t, filepath.Join(ca, "certs", name+"_ecc", name+".cer")))
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if cert.SerialNumber.Int64() != want {
			t.Fatalf("%s: expected serial %d, got %s", name, want, cert.SerialNumber)
		}
	}
}

func TestRevokeCRL(t *testing.T) {
	ca := filepath.Join(t.TempDir(), "ca")
	exec(t, "root", "-D", ca)
	exec(t, "inte", "-D", ca, "-c", filepath.Join(ca, "RootCA.cer"), "-k", filepath.Join(ca, "RootCA.key"))
	exec(t, "cert", "-D", ca, "-d", "example.com", "-d", "www.example.com")

	exec(t, "db", "revoke", "example.com", "-D", ca)
	crl := loadCRL(t, filepath.Join(ca, "crl", "InteCA.crl"))
	if len(crl.RevokedCertificateEntries) != 1 {
		t.Fatalf("expected 1 revoked entry, got %d", len(crl.RevokedCertificateEntries))
	}
	block, _ := pem.Decode(mustRead(t, filepath.Join(ca, "InteCA.cer")))
	issuer, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := crl.CheckSignatureFrom(issuer); err != nil {
		t.Fatalf("CRL signature invalid: %v", err)
	}

	exec(t, "db", "unrevoke", "example.com", "-D", ca)
	if crl = loadCRL(t, filepath.Join(ca, "crl", "InteCA.crl")); len(crl.RevokedCertificateEntries) != 0 {
		t.Fatalf("expected 0 revoked entries after unrevoke, got %d", len(crl.RevokedCertificateEntries))
	}
}

func TestNoSubjectKeyID(t *testing.T) {
	ca := filepath.Join(t.TempDir(), "ca")
	exec(t, "root", "-D", ca, "--subject-key-id=false")
	block, _ := pem.Decode(mustRead(t, filepath.Join(ca, "RootCA.cer")))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.SubjectKeyId) != 0 {
		t.Fatalf("expected no subject key id, got %x", cert.SubjectKeyId)
	}
	if !cert.IsCA {
		t.Fatal("expected CA certificate")
	}
}

func exec(t *testing.T, args ...string) {
	t.Helper()
	cmd := newCLI()
	cmd.SetArgs(args)
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
}

func loadCRL(t *testing.T, path string) *x509.RevocationList {
	t.Helper()
	block, _ := pem.Decode(mustRead(t, path))
	if block == nil {
		t.Fatalf("failed to decode CRL: %s", path)
	}
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return crl
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
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
