package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseSubject(t *testing.T) {
	name := ParseSubject("/C=CN/ST=Zhejiang/L=Hangzhou/O=Org/OU=Unit/CN=host/emailAddress=a@b")
	if len(name.Country) != 1 || name.Country[0] != "CN" {
		t.Fatalf("unexpected country: %v", name.Country)
	}
	if name.Province[0] != "Zhejiang" || name.Locality[0] != "Hangzhou" {
		t.Fatalf("unexpected location: %v %v", name.Province, name.Locality)
	}
	if name.Organization[0] != "Org" || name.OrganizationalUnit[0] != "Unit" {
		t.Fatalf("unexpected organization: %v %v", name.Organization, name.OrganizationalUnit)
	}
	if name.CommonName != "host" {
		t.Fatalf("unexpected common name: %q", name.CommonName)
	}
	if len(name.ExtraNames) != 1 {
		t.Fatalf("unexpected email attribute: %v", name.ExtraNames)
	}
}

func TestParseKeyUsage(t *testing.T) {
	usage, err := ParseKeyUsage([]string{"digitalSignature", "keyCertSign", "crlSign"})
	if err != nil {
		t.Fatal(err)
	}
	want := x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	if usage != want {
		t.Fatalf("unexpected key usage: %v", usage)
	}
	if _, err := ParseKeyUsage([]string{"nonsense"}); err == nil {
		t.Fatal("expected error for unknown key usage")
	}
}

func TestParseExtKeyUsage(t *testing.T) {
	usages, err := ParseExtKeyUsage([]string{"serverAuth", "clientAuth"})
	if err != nil {
		t.Fatal(err)
	}
	if len(usages) != 2 || usages[0] != x509.ExtKeyUsageServerAuth || usages[1] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("unexpected extended key usage: %v", usages)
	}
	if _, err := ParseExtKeyUsage([]string{"nonsense"}); err == nil {
		t.Fatal("expected error for unknown extended key usage")
	}
}

func TestSignatureAlgorithm(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SignatureAlgorithm("md5", ecKey); err == nil {
		t.Fatal("expected error for unsupported digest")
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	algorithm, err := SignatureAlgorithm("sha256", rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	if algorithm != x509.SHA256WithRSA {
		t.Fatalf("unexpected algorithm: %v", algorithm)
	}
}

func TestKeyCipher(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	if got := KeyCipher(ecKey.Public()); got != "ecc" {
		t.Fatalf("unexpected cipher: %s", got)
	}
	if got := KeyCipher(rsaKey.Public()); got != "rsa" {
		t.Fatalf("unexpected cipher: %s", got)
	}
	if got := KeyCipher(ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))); got != "ed25519" {
		t.Fatalf("unexpected cipher: %s", got)
	}
}

func TestLeafKeyUsage(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if got := LeafKeyUsage(ecKey.Public()); got != x509.KeyUsageDigitalSignature {
		t.Fatalf("unexpected ECDSA key usage: %v", got)
	}
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	want := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	if got := LeafKeyUsage(rsaKey.Public()); got != want {
		t.Fatalf("unexpected RSA key usage: %v", got)
	}
}

func TestValidUntil(t *testing.T) {
	now := time.Now()
	issuer := &x509.Certificate{NotAfter: now.Add(10 * 24 * time.Hour)}
	if got := ValidUntil(issuer, 30, now); !got.Equal(issuer.NotAfter) {
		t.Fatalf("expected issuer NotAfter, got %v", got)
	}
	if got := ValidUntil(issuer, 5, now); !got.Equal(now.Add(5 * 24 * time.Hour)) {
		t.Fatalf("expected requested NotAfter, got %v", got)
	}
	if got := ValidUntil(nil, 5, now); !got.Equal(now.Add(5 * 24 * time.Hour)) {
		t.Fatalf("expected requested NotAfter, got %v", got)
	}
}

func TestIssueSelfSignedCAPath(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	cert, _, err := IssueSelfSigned(key, IssueOptions{
		Serial:       big.NewInt(1),
		NotBefore:    now,
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:         true,
		PathLength:   0,
		SubjectKeyID: true,
		Digest:       "sha512",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !cert.IsCA || !cert.MaxPathLenZero {
		t.Fatalf("expected CA with path length 0, got IsCA=%v MaxPathLen=%d", cert.IsCA, cert.MaxPathLen)
	}
	if len(cert.SubjectKeyId) == 0 {
		t.Fatal("expected subject key identifier")
	}

	cert, _, err = IssueSelfSigned(key, IssueOptions{
		Serial:       big.NewInt(2),
		NotBefore:    now,
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageCertSign,
		IsCA:         true,
		PathLength:   2,
		SubjectKeyID: false,
		Digest:       "sha512",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !cert.IsCA || cert.MaxPathLen != 2 {
		t.Fatalf("expected CA with path length 2, got IsCA=%v MaxPathLen=%d", cert.IsCA, cert.MaxPathLen)
	}
	if len(cert.SubjectKeyId) != 0 {
		t.Fatalf("expected no subject key identifier, got %x", cert.SubjectKeyId)
	}
}

func TestLoadLegacyECKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	var pemData bytes.Buffer
	pemData.Write(pem.EncodeToMemory(&pem.Block{Type: "EC PARAMETERS", Bytes: []byte("params")}))
	pemData.Write(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
	path := filepath.Join(t.TempDir(), "legacy.key")
	if err := os.WriteFile(path, pemData.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !publicKeysEqual(loaded.Public(), key.Public()) {
		t.Fatal("loaded legacy key does not match")
	}
}
