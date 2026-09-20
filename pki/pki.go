package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"
)

var (
	oidEmail            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
	oidBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
)

type IssueOptions struct {
	Serial         *big.Int
	Subject        pkix.Name
	NotBefore      time.Time
	NotAfter       time.Time
	KeyUsage       x509.KeyUsage
	ExtKeyUsage    []x509.ExtKeyUsage
	DNSNames       []string
	Digest         string
	IsCA           bool
	PathLength     int
	SubjectKeyID   bool
	AuthorityKeyID bool
}

func ParseSubject(s string) pkix.Name {
	var n pkix.Name
	for _, part := range strings.Split(s, "/") {
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		k, v := strings.TrimSpace(strings.ToUpper(kv[0])), kv[1]
		switch k {
		case "C":
			n.Country = append(n.Country, v)
		case "ST", "S":
			n.Province = append(n.Province, v)
		case "L":
			n.Locality = append(n.Locality, v)
		case "O":
			n.Organization = append(n.Organization, v)
		case "OU":
			n.OrganizationalUnit = append(n.OrganizationalUnit, v)
		case "CN":
			n.CommonName = v
		case "EMAILADDRESS", "E":
			n.ExtraNames = append(n.ExtraNames, pkix.AttributeTypeAndValue{Type: oidEmail, Value: v})
		}
	}
	return n
}

func ValidateCipher(cipher string) error {
	switch cipher {
	case "ecc", "rsa":
		return nil
	default:
		return fmt.Errorf("unsupported cipher %q, supported: ecc, rsa", cipher)
	}
}

func GenerateKey(cipher string, bits int) (crypto.Signer, []byte, error) {
	if err := ValidateCipher(cipher); err != nil {
		return nil, nil, err
	}
	switch cipher {
	case "ecc":
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		der, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, nil, err
		}
		return key, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
	case "rsa":
		if bits < 2048 {
			return nil, nil, fmt.Errorf("RSA key length too small: %d, minimum is 2048", bits)
		}
		key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, nil, err
		}
		return key, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), nil
	default:
		return nil, nil, fmt.Errorf("unsupported cipher %q, supported: ecc, rsa", cipher)
	}
}

func EnsureKey(path, cipher string, bits int) (crypto.Signer, error) {
	if err := ValidateCipher(cipher); err != nil {
		return nil, err
	}
	if Exists(path) {
		key, err := LoadKey(path)
		if err != nil {
			return nil, err
		}
		if got := KeyCipher(key.Public()); got != cipher {
			return nil, fmt.Errorf("existing key %s is %s, not %s", path, got, cipher)
		}
		return key, nil
	}
	key, keyPEM, err := GenerateKey(cipher, bits)
	if err != nil {
		return nil, err
	}
	if err := WriteFile(path, keyPEM, 0600); err != nil {
		return nil, err
	}
	return key, nil
}

func LoadKey(path string) (crypto.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM key: %s", path)
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		switch k := key.(type) {
		case *rsa.PrivateKey:
			return k, nil
		case *ecdsa.PrivateKey:
			return k, nil
		}
	}
	return nil, fmt.Errorf("unsupported private key: %s", path)
}

func LoadCert(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM certificate: %s", path)
	}
	return x509.ParseCertificate(block.Bytes)
}

func LoadCSR(path string) (*x509.CertificateRequest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM certificate request: %s", path)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("invalid certificate request signature: %w", err)
	}
	return csr, nil
}

func EncodeCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func EnsureCSR(path string, subject pkix.Name, dnsNames []string, signer crypto.Signer) error {
	if Exists(path) {
		existing, err := LoadCSR(path)
		if err == nil && existing.Subject.String() == subject.String() && sameStringSet(existing.DNSNames, dnsNames) {
			return nil
		}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: subject, DNSNames: dnsNames}, signer)
	if err != nil {
		return err
	}
	return WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), 0644)
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	set := make(map[string]struct{}, len(a))
	for _, value := range a {
		set[value] = struct{}{}
	}
	for _, value := range b {
		if _, ok := set[value]; !ok {
			return false
		}
	}
	return true
}

func RandomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, err
	}
	if n.Sign() == 0 {
		n = big.NewInt(1)
	}
	return n, nil
}

func SubjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	sum := sha1.Sum(der)
	return sum[:], nil
}

func AuthorityKeyID(issuer *x509.Certificate) []byte {
	if len(issuer.SubjectKeyId) > 0 {
		return issuer.SubjectKeyId
	}
	id, err := SubjectKeyID(issuer.PublicKey)
	if err != nil {
		return nil
	}
	return id
}

func ValidUntil(issuer *x509.Certificate, days int, now time.Time) time.Time {
	notAfter := now.AddDate(0, 0, days)
	if issuer != nil && issuer.NotAfter.Before(notAfter) {
		return issuer.NotAfter
	}
	return notAfter
}

func ValidateCA(cert *x509.Certificate) error {
	if !cert.IsCA {
		return fmt.Errorf("issuer is not a CA certificate")
	}
	if cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return fmt.Errorf("issuer does not permit certificate signing")
	}
	return nil
}

func ValidateCRLSigner(cert *x509.Certificate) error {
	if err := ValidateCA(cert); err != nil {
		return err
	}
	if cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageCRLSign == 0 {
		return fmt.Errorf("issuer does not permit CRL signing")
	}
	return nil
}

func SignatureAlgorithm(digest string, key crypto.Signer) (x509.SignatureAlgorithm, error) {
	switch key.(type) {
	case *rsa.PrivateKey:
		switch digest {
		case "sha256":
			return x509.SHA256WithRSA, nil
		case "sha384":
			return x509.SHA384WithRSA, nil
		case "sha512", "":
			return x509.SHA512WithRSA, nil
		}
	case *ecdsa.PrivateKey:
		switch digest {
		case "sha256":
			return x509.ECDSAWithSHA256, nil
		case "sha384":
			return x509.ECDSAWithSHA384, nil
		case "sha512", "":
			return x509.ECDSAWithSHA512, nil
		}
	}
	return x509.UnknownSignatureAlgorithm, fmt.Errorf("unsupported digest %q for this key type", digest)
}

func KeyCipher(publicKey crypto.PublicKey) string {
	switch publicKey.(type) {
	case *rsa.PublicKey:
		return "rsa"
	case *ecdsa.PublicKey:
		return "ecc"
	case ed25519.PublicKey:
		return "ed25519"
	default:
		return "unknown"
	}
}

func LeafKeyUsage(publicKey crypto.PublicKey) x509.KeyUsage {
	if _, ok := publicKey.(*rsa.PublicKey); ok {
		return x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	}
	return x509.KeyUsageDigitalSignature
}

var keyUsageNames = map[string]x509.KeyUsage{
	"digitalSignature":  x509.KeyUsageDigitalSignature,
	"nonRepudiation":    x509.KeyUsageContentCommitment,
	"contentCommitment": x509.KeyUsageContentCommitment,
	"keyEncipherment":   x509.KeyUsageKeyEncipherment,
	"dataEncipherment":  x509.KeyUsageDataEncipherment,
	"keyAgreement":      x509.KeyUsageKeyAgreement,
	"keyCertSign":       x509.KeyUsageCertSign,
	"cRLSign":           x509.KeyUsageCRLSign,
	"crlSign":           x509.KeyUsageCRLSign,
	"encipherOnly":      x509.KeyUsageEncipherOnly,
	"decipherOnly":      x509.KeyUsageDecipherOnly,
}

var extKeyUsageNames = map[string]x509.ExtKeyUsage{
	"serverAuth":          x509.ExtKeyUsageServerAuth,
	"clientAuth":          x509.ExtKeyUsageClientAuth,
	"codeSigning":         x509.ExtKeyUsageCodeSigning,
	"emailProtection":     x509.ExtKeyUsageEmailProtection,
	"ipsecEndSystem":      x509.ExtKeyUsageIPSECEndSystem,
	"ipsecTunnel":         x509.ExtKeyUsageIPSECTunnel,
	"ipsecUser":           x509.ExtKeyUsageIPSECUser,
	"timeStamping":        x509.ExtKeyUsageTimeStamping,
	"ocspSigning":         x509.ExtKeyUsageOCSPSigning,
	"OCSPSigning":         x509.ExtKeyUsageOCSPSigning,
	"any":                 x509.ExtKeyUsageAny,
	"anyExtendedKeyUsage": x509.ExtKeyUsageAny,
}

func ParseKeyUsage(names []string) (x509.KeyUsage, error) {
	var usage x509.KeyUsage
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		v, ok := keyUsageNames[name]
		if !ok {
			return 0, fmt.Errorf("unknown key usage: %s", name)
		}
		usage |= v
	}
	return usage, nil
}

func ParseExtKeyUsage(names []string) ([]x509.ExtKeyUsage, error) {
	var usages []x509.ExtKeyUsage
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		v, ok := extKeyUsageNames[name]
		if !ok {
			return nil, fmt.Errorf("unknown extended key usage: %s", name)
		}
		usages = append(usages, v)
	}
	return usages, nil
}

func IssueSelfSigned(key crypto.Signer, o IssueOptions) (*x509.Certificate, []byte, error) {
	sig, err := SignatureAlgorithm(o.Digest, key)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:       o.Serial,
		Subject:            o.Subject,
		NotBefore:          o.NotBefore,
		NotAfter:           o.NotAfter,
		KeyUsage:           o.KeyUsage,
		ExtKeyUsage:        o.ExtKeyUsage,
		SignatureAlgorithm: sig,
	}
	if err := applyCAOptions(tmpl, o, key.Public()); err != nil {
		return nil, nil, err
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, der, nil
}

func Issue(publicKey crypto.PublicKey, parent *x509.Certificate, parentKey crypto.Signer, o IssueOptions) (*x509.Certificate, []byte, error) {
	sig, err := SignatureAlgorithm(o.Digest, parentKey)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:       o.Serial,
		Subject:            o.Subject,
		NotBefore:          o.NotBefore,
		NotAfter:           o.NotAfter,
		KeyUsage:           o.KeyUsage,
		ExtKeyUsage:        o.ExtKeyUsage,
		DNSNames:           o.DNSNames,
		SignatureAlgorithm: sig,
	}
	if o.IsCA {
		if err := applyCAOptions(tmpl, o, publicKey); err != nil {
			return nil, nil, err
		}
	} else {
		tmpl.BasicConstraintsValid = true
	}
	if o.AuthorityKeyID {
		tmpl.AuthorityKeyId = AuthorityKeyID(parent)
	} else {
		// Prevent the stdlib from deriving an authority key identifier.
		parentCopy := *parent
		parentCopy.SubjectKeyId = nil
		parent = &parentCopy
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, publicKey, parentKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, der, nil
}

func applyCAOptions(tmpl *x509.Certificate, o IssueOptions, publicKey crypto.PublicKey) error {
	if o.SubjectKeyID {
		tmpl.IsCA = true
		tmpl.BasicConstraintsValid = true
		if o.PathLength >= 0 {
			tmpl.MaxPathLen = o.PathLength
			tmpl.MaxPathLenZero = o.PathLength == 0
		}
		skid, err := SubjectKeyID(publicKey)
		if err != nil {
			return err
		}
		tmpl.SubjectKeyId = skid
		return nil
	}
	// Keep IsCA false so the stdlib does not force a subject key identifier,
	// then encode basicConstraints ourselves.
	value, err := marshalBasicConstraints(o.PathLength)
	if err != nil {
		return err
	}
	tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{Id: oidBasicConstraints, Critical: true, Value: value})
	return nil
}

func marshalBasicConstraints(pathLength int) ([]byte, error) {
	if pathLength < 0 {
		return asn1.Marshal(struct {
			IsCA bool `asn1:"optional"`
		}{true})
	}
	return asn1.Marshal(struct {
		IsCA       bool `asn1:"optional"`
		MaxPathLen int
	}{true, pathLength})
}

func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func WriteFile(path string, data []byte, perm os.FileMode) error {
	if err := os.WriteFile(path, data, perm); err != nil {
		return fmt.Errorf("failed to write %s: %w", path, err)
	}
	return nil
}
