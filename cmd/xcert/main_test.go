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
	"strings"
	"testing"

	"github.com/xireiki/xcert/store"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
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

func TestCertExtKeyUsage(t *testing.T) {
	ca := filepath.Join(t.TempDir(), "ca")
	exec(t, "root", "-D", ca)
	exec(t, "inte", "-D", ca, "-c", filepath.Join(ca, "RootCA.cer"), "-k", filepath.Join(ca, "RootCA.key"))
	exec(t, "cert", "-D", ca, "-d", "eku.test", "--ext-key-usage", "clientAuth")

	block, _ := pem.Decode(mustRead(t, filepath.Join(ca, "certs", "eku.test_ecc", "eku.test.cer")))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("expected only clientAuth, got %v", cert.ExtKeyUsage)
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

func TestInfo(t *testing.T) {
	ca := filepath.Join(t.TempDir(), "ca")
	exec(t, "root", "-D", ca)
	certPath := filepath.Join(ca, "RootCA.cer")

	cmd := newCLI()
	out := &strings.Builder{}
	cmd.SetOut(out)
	cmd.SetArgs([]string{"info", "-f", certPath})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	if !strings.Contains(text, "Subject:") || !strings.Contains(text, "IsCA:          true") {
		t.Fatalf("unexpected info output:\n%s", text)
	}
}

func TestCodeSigning(t *testing.T) {
	ca := filepath.Join(t.TempDir(), "ca")
	exec(t, "root", "-D", ca)
	exec(t, "inte", "-D", ca, "-c", filepath.Join(ca, "RootCA.cer"), "-k", filepath.Join(ca, "RootCA.key"))
	exec(t, "cert", "-D", ca, "-d", "sign.test", "--code-signing", "--pfx-password", "secret")

	dir := filepath.Join(ca, "certs", "sign.test_ecc")
	block, _ := pem.Decode(mustRead(t, filepath.Join(dir, "sign.test.cer")))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageCodeSigning {
		t.Fatalf("expected only codeSigning, got %v", cert.ExtKeyUsage)
	}
	if cert.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Fatalf("expected digitalSignature only, got %v", cert.KeyUsage)
	}
	if _, err := os.Stat(filepath.Join(dir, "fullchain.cer")); !os.IsNotExist(err) {
		t.Fatal("expected no fullchain.cer for a code signing certificate")
	}

	pfxData := mustRead(t, filepath.Join(dir, "sign.test.pfx"))
	key, pfxCert, caCerts, err := pkcs12.DecodeChain(pfxData, "secret")
	if err != nil {
		t.Fatal(err)
	}
	if key == nil || pfxCert.Subject.CommonName != "sign.test" {
		t.Fatal("pfx does not contain the expected key and certificate")
	}
	if len(caCerts) != 2 {
		t.Fatalf("expected 2 CA certificates in the pfx, got %d", len(caCerts))
	}
	if _, _, _, err := pkcs12.DecodeChain(pfxData, "wrong"); err == nil {
		t.Fatal("expected a wrong pfx password to fail")
	}

	if err := execErr("cert", "-D", ca, "-d", "both.test", "--code-signing", "--ext-key-usage", "serverAuth"); err == nil {
		t.Fatal("expected --code-signing and --ext-key-usage to be rejected together")
	}
}

func TestCodeSigningIssuerRestriction(t *testing.T) {
	ca := filepath.Join(t.TempDir(), "ca")
	exec(t, "root", "-D", ca)
	exec(t, "inte", "-D", ca, "-c", filepath.Join(ca, "RootCA.cer"), "-k", filepath.Join(ca, "RootCA.key"), "--ext-key-usage", "serverAuth")
	if err := execErr("cert", "-D", ca, "-d", "sign.test", "--code-signing"); err == nil {
		t.Fatal("expected the restricted issuer to reject code signing")
	}
}

func TestDBImport(t *testing.T) {
	ca := filepath.Join(t.TempDir(), "ca")
	exec(t, "root", "-D", ca)
	if err := os.Remove(filepath.Join(ca, store.FileName)); err != nil {
		t.Fatal(err)
	}
	exec(t, "db", "import", filepath.Join(ca, "RootCA.cer"), "-D", ca, "--name", "RootCA")

	st, err := store.Open(filepath.Join(ca, store.FileName))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	records, err := st.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Type != "root" || records[0].Name != "RootCA" {
		t.Fatalf("unexpected imported records: %+v", records)
	}
	if !filepath.IsAbs(records[0].CertPath) {
		t.Fatalf("expected an absolute cert path, got %s", records[0].CertPath)
	}
	if err := execErr("db", "import", filepath.Join(ca, "RootCA.cer"), "-D", ca, "--type", "cert"); err == nil {
		t.Fatal("expected the removed --type flag to be rejected")
	}
}

func TestDeleteKeepsCAFiles(t *testing.T) {
	ca := filepath.Join(t.TempDir(), "ca")
	exec(t, "root", "-D", ca)
	exec(t, "inte", "-D", ca, "-c", filepath.Join(ca, "RootCA.cer"), "-k", filepath.Join(ca, "RootCA.key"))
	exec(t, "db", "delete", "InteCA", "-D", ca)
	for _, name := range []string{"InteCA.cer", "InteCA.csr"} {
		if _, err := os.Stat(filepath.Join(ca, name)); err != nil {
			t.Fatalf("expected %s to survive db delete: %v", name, err)
		}
	}
}

func TestDBImportRequiresIssuer(t *testing.T) {
	ca := filepath.Join(t.TempDir(), "ca")
	exec(t, "root", "-D", ca)
	exec(t, "inte", "-D", ca, "-c", filepath.Join(ca, "RootCA.cer"), "-k", filepath.Join(ca, "RootCA.key"))
	exec(t, "cert", "-D", ca, "-d", "example.com")
	if err := os.Remove(filepath.Join(ca, store.FileName)); err != nil {
		t.Fatal(err)
	}
	leaf := filepath.Join(ca, "certs", "example.com_ecc", "example.com.cer")
	if err := execErr("db", "import", leaf, "-D", ca); err == nil {
		t.Fatal("expected importing a leaf without its issuer in the database to fail")
	}
}

func TestRevokeCARejected(t *testing.T) {
	ca := filepath.Join(t.TempDir(), "ca")
	exec(t, "root", "-D", ca)
	exec(t, "inte", "-D", ca, "-c", filepath.Join(ca, "RootCA.cer"), "-k", filepath.Join(ca, "RootCA.key"))
	if err := execErr("db", "revoke", "InteCA", "-D", ca); err == nil {
		t.Fatal("expected revoking an intermediate CA to be rejected")
	}
	if _, err := os.Stat(filepath.Join(ca, "crl", "InteCA.crl")); !os.IsNotExist(err) {
		t.Fatal("expected no CRL to be written when the CA revoke is rejected")
	}
	st, err := store.Open(filepath.Join(ca, store.FileName))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	record, err := st.Resolve("InteCA")
	if err != nil {
		t.Fatal(err)
	}
	if record.Status != "V" {
		t.Fatalf("expected the CA record to stay valid, got %s", record.Status)
	}
}

func TestDeleteLeafWithoutCert(t *testing.T) {
	ca := filepath.Join(t.TempDir(), "ca")
	exec(t, "root", "-D", ca)
	exec(t, "inte", "-D", ca, "-c", filepath.Join(ca, "RootCA.cer"), "-k", filepath.Join(ca, "RootCA.key"))
	exec(t, "cert", "-D", ca, "-d", "two.example.com")
	dir := filepath.Join(ca, "certs", "two.example.com_ecc")
	if err := os.Remove(filepath.Join(dir, "two.example.com.cer")); err != nil {
		t.Fatal(err)
	}
	exec(t, "db", "delete", "two.example.com", "-D", ca)
	for _, name := range []string{"two.example.com.key", "two.example.com.csr", "fullchain.cer"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatalf("expected %s to be removed, got err=%v", name, err)
		}
	}
}

func exec(t *testing.T, args ...string) {
	t.Helper()
	if err := execErr(args...); err != nil {
		t.Fatal(err)
	}
}

func execErr(args ...string) error {
	cmd := newCLI()
	cmd.SetArgs(args)
	return cmd.Execute()
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
