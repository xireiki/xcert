package main

import (
	"crypto"
	"crypto/ecdsa"
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
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

const (
	defaultRootSubject = "/C=CN/O=Test SSL/CN=Test SSL CA"
	defaultInteSubject = "/C=CN/O=Test SSL/CN=Test Inte CA"
	defaultCertSubject = "/C=CN"
)

var (
	progName = filepath.Base(os.Args[0])
	color    = os.Getenv("TERM") == "xterm-256color"
	oidEmail = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
)

func info(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	if color {
		fmt.Printf("\033[32mINFO\033[0m %s", msg)
	} else {
		fmt.Printf("INFO %s", msg)
	}
}

func warn(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	if color {
		fmt.Printf("\033[33mWARN\033[0m %s", msg)
	} else {
		fmt.Printf("WARN %s", msg)
	}
}

func erro(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	if color {
		fmt.Fprintf(os.Stderr, "\033[31mERRO\033[0m %s", msg)
	} else {
		fmt.Fprintf(os.Stderr, "ERRO %s", msg)
	}
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func writeFile(path string, data []byte, perm os.FileMode) error {
	if err := os.WriteFile(path, data, perm); err != nil {
		return fmt.Errorf("failed to write %s: %w", path, err)
	}
	return nil
}

func parseSubject(s string) pkix.Name {
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

func generateKey(cipher string, bits int) (crypto.Signer, []byte, error) {
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
		if bits < 512 {
			return nil, nil, fmt.Errorf("RSA key length too small: %d", bits)
		}
		key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, nil, err
		}
		return key, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), nil
	default:
		return nil, nil, fmt.Errorf("Unknown private key type: %s", cipher)
	}
}

func loadKey(path string) (crypto.Signer, error) {
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

func loadCert(path string) (*x509.Certificate, error) {
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

func sigAlg(key crypto.Signer) x509.SignatureAlgorithm {
	switch key.(type) {
	case *rsa.PrivateKey:
		return x509.SHA512WithRSA
	case *ecdsa.PrivateKey:
		return x509.ECDSAWithSHA512
	}
	return x509.UnknownSignatureAlgorithm
}

func randomSerial() (*big.Int, error) {
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

func subjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	sum := sha1.Sum(der)
	return sum[:], nil
}

func encodeCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

type keyOptions struct {
	cipher  string
	bits    int
	subject string
	days    int
}

func addKeyFlags(cmd *cobra.Command, o *keyOptions, defaults keyOptions) {
	f := cmd.Flags()
	f.StringVarP(&o.cipher, "cipher", "C", defaults.cipher, "encryption method for the private key")
	f.IntVar(&o.bits, "rsa-bits", defaults.bits, "key length for RSA private keys")
	f.StringVarP(&o.subject, "subject", "s", defaults.subject, "subject information")
	f.IntVar(&o.days, "days", defaults.days, "expiration time in days")
}

type caOptions struct {
	keyUsage       []string
	extKeyUsage    []string
	pathLength     int
	digest         string
	subjectKeyID   bool
	authorityKeyID bool
}

func addCAFlags(cmd *cobra.Command, o *caOptions, defaults caOptions) {
	f := cmd.Flags()
	f.StringSliceVar(&o.keyUsage, "key-usage", defaults.keyUsage, "key usage extension (comma separated)")
	f.StringSliceVar(&o.extKeyUsage, "ext-key-usage", defaults.extKeyUsage, "extended key usage extension (comma separated)")
	f.IntVar(&o.pathLength, "path-length", defaults.pathLength, "CA path length, -1 for unset")
	f.StringVar(&o.digest, "digest", defaults.digest, "signature digest algorithm (sha256, sha384, sha512)")
	f.BoolVar(&o.subjectKeyID, "subject-key-id", defaults.subjectKeyID, "include subject key identifier")
	f.BoolVar(&o.authorityKeyID, "authority-key-id", defaults.authorityKeyID, "include authority key identifier")
}

var oidBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}

func applyCAOptions(tmpl *x509.Certificate, o *caOptions, publicKey crypto.PublicKey) error {
	if o.subjectKeyID {
		tmpl.IsCA = true
		tmpl.BasicConstraintsValid = true
		if o.pathLength >= 0 {
			tmpl.MaxPathLen = o.pathLength
			tmpl.MaxPathLenZero = o.pathLength == 0
		}
		skid, err := subjectKeyID(publicKey)
		if err != nil {
			return err
		}
		tmpl.SubjectKeyId = skid
		return nil
	}
	// Keep IsCA false so the stdlib does not force a subject key identifier,
	// then encode basicConstraints ourselves.
	if o.pathLength < 0 {
		value, err := asn1.Marshal(struct {
			IsCA bool `asn1:"optional"`
		}{true})
		if err != nil {
			return err
		}
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{Id: oidBasicConstraints, Critical: true, Value: value})
		return nil
	}
	value, err := asn1.Marshal(struct {
		IsCA       bool `asn1:"optional"`
		MaxPathLen int
	}{true, o.pathLength})
	if err != nil {
		return err
	}
	tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{Id: oidBasicConstraints, Critical: true, Value: value})
	return nil
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

var extKeyUsageNames = map[string]x509.ExtKeyUsage{"serverAuth": x509.ExtKeyUsageServerAuth,
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

func parseKeyUsage(names []string) (x509.KeyUsage, error) {
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

func parseExtKeyUsage(names []string) ([]x509.ExtKeyUsage, error) {
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

func signatureAlgorithm(md string, key crypto.Signer) (x509.SignatureAlgorithm, error) {
	switch key.(type) {
	case *rsa.PrivateKey:
		switch md {
		case "sha256":
			return x509.SHA256WithRSA, nil
		case "sha384":
			return x509.SHA384WithRSA, nil
		case "sha512", "":
			return x509.SHA512WithRSA, nil
		}
	case *ecdsa.PrivateKey:
		switch md {
		case "sha256":
			return x509.ECDSAWithSHA256, nil
		case "sha384":
			return x509.ECDSAWithSHA384, nil
		case "sha512", "":
			return x509.ECDSAWithSHA512, nil
		}
	}
	return x509.UnknownSignatureAlgorithm, fmt.Errorf("unsupported md %q for this key type", md)
}

type rootOptions struct {
	keyOptions
	caOptions
	dir string
}

func newRootCmd() *cobra.Command {
	o := &rootOptions{}
	cmd := &cobra.Command{
		Use:           "root",
		Short:         "Create a root certificate",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if cmd.Flags().NFlag() == 0 && len(args) == 0 {
				cmd.Help()
				return nil
			}
			return runRoot(o)
		},
	}
	addKeyFlags(cmd, &o.keyOptions, keyOptions{cipher: "ecc", bits: 3072, subject: defaultRootSubject, days: 3650})
	addCAFlags(cmd, &o.caOptions, caOptions{pathLength: -1, digest: "sha512", subjectKeyID: true, authorityKeyID: true})
	cmd.Flags().StringVarP(&o.dir, "dir", "D", ".", "certificate directory")
	cmd.SetHelpFunc(func(cmd *cobra.Command, args []string) { helpWithRootCommand() })
	return cmd
}

func runRoot(o *rootOptions) error {
	certPath := filepath.Join(o.dir, "RootCA.cer")
	if exists(certPath) {
		warn("Root certificate already exists\n")
		return nil
	}
	for _, d := range []string{filepath.Join(o.dir, "newcerts"), filepath.Join(o.dir, "crl")} {
		if err := os.MkdirAll(d, 0755); err != nil {
			return err
		}
	}

	keyPath := filepath.Join(o.dir, "RootCA.key")
	if !exists(keyPath) {
		_, keyPEM, err := generateKey(o.cipher, o.bits)
		if err != nil {
			return err
		}
		if err := writeFile(keyPath, keyPEM, 0600); err != nil {
			return err
		}
	}

	if !exists(certPath) {
		key, err := loadKey(keyPath)
		if err != nil {
			return err
		}
		serial, err := randomSerial()
		if err != nil {
			return err
		}
		usage, err := parseKeyUsage(o.keyUsage)
		if err != nil {
			return err
		}
		extUsage, err := parseExtKeyUsage(o.extKeyUsage)
		if err != nil {
			return err
		}
		sig, err := signatureAlgorithm(o.digest, key)
		if err != nil {
			return err
		}
		now := time.Now()
		tmpl := &x509.Certificate{
			SerialNumber:       serial,
			Subject:            parseSubject(o.subject),
			NotBefore:          now,
			NotAfter:           now.AddDate(0, 0, o.days),
			KeyUsage:           usage,
			ExtKeyUsage:        extUsage,
			SignatureAlgorithm: sig,
		}
		if err := applyCAOptions(tmpl, &o.caOptions, key.Public()); err != nil {
			return err
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
		if err != nil {
			return err
		}
		if err := writeFile(certPath, encodeCert(der), 0644); err != nil {
			return err
		}
		st, err := openStore(filepath.Join(o.dir, dbFileName))
		if err != nil {
			return err
		}
		defer st.close()
		if err := st.record(serial, tmpl.Subject.String(), "root", "RootCA", certPath, keyPath, now, tmpl.NotAfter); err != nil {
			return err
		}
	}

	if exists(keyPath) && exists(certPath) {
		info("Done.\n")
	}
	return nil
}

type inteOptions struct {
	keyOptions
	caOptions
	dir        string
	cert       string
	key        string
	randSerial bool
}

func newInteCmd() *cobra.Command {
	o := &inteOptions{}
	cmd := &cobra.Command{
		Use:           "inte",
		Short:         "Create Intermediate Certificate",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if cmd.Flags().NFlag() == 0 && len(args) == 0 {
				cmd.Help()
				return nil
			}
			return runInte(o)
		},
	}
	addKeyFlags(cmd, &o.keyOptions, keyOptions{cipher: "ecc", bits: 3072, subject: defaultInteSubject, days: 1825})
	addCAFlags(cmd, &o.caOptions, caOptions{keyUsage: []string{"keyCertSign", "cRLSign"}, extKeyUsage: []string{"serverAuth", "clientAuth"}, pathLength: 0, digest: "sha512", subjectKeyID: true, authorityKeyID: true})
	f := cmd.Flags()
	f.StringVarP(&o.dir, "dir", "D", ".", "certificate directory")
	f.StringVarP(&o.cert, "cert", "c", "", "intermediate certificate")
	f.StringVarP(&o.key, "key", "k", "", "intermediate certificate key")
	f.BoolVarP(&o.randSerial, "random-serial", "R", false, "use a random serial number")
	cmd.SetHelpFunc(func(cmd *cobra.Command, args []string) { helpWithInteCommand() })
	return cmd
}

func runInte(o *inteOptions) error {
	certPath := filepath.Join(o.dir, "InteCA.cer")
	if exists(certPath) {
		warn("Intermediate certificate already exists\n")
		return nil
	}
	if o.cert == "" || o.key == "" {
		return fmt.Errorf("intermediate CA requires -c/--cert and -k/--key")
	}
	if !exists(o.cert) {
		return fmt.Errorf("certificate not found: %s", o.cert)
	}
	if !exists(o.key) {
		return fmt.Errorf("key not found: %s", o.key)
	}
	for _, d := range []string{"newcerts", "crl", "certs"} {
		if err := os.MkdirAll(filepath.Join(o.dir, d), 0755); err != nil {
			return err
		}
	}
	st, err := openStore(filepath.Join(o.dir, dbFileName))
	if err != nil {
		return err
	}
	defer st.close()
	info("Refresh Database\n")

	info("Start generating certificate\n")
	keyPath := filepath.Join(o.dir, "InteCA.key")
	if !exists(keyPath) {
		_, keyPEM, err := generateKey(o.cipher, o.bits)
		if err != nil {
			return err
		}
		if err := writeFile(keyPath, keyPEM, 0600); err != nil {
			return err
		}
	}
	keySigner, err := loadKey(keyPath)
	if err != nil {
		return err
	}

	csrPath := filepath.Join(o.dir, "InteCA.csr")
	if !exists(csrPath) {
		der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: parseSubject(o.subject)}, keySigner)
		if err != nil {
			return err
		}
		if err := writeFile(csrPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), 0644); err != nil {
			return err
		}
	}

	if !exists(certPath) {
		parentCert, err := loadCert(o.cert)
		if err != nil {
			return err
		}
		parentKey, err := loadKey(o.key)
		if err != nil {
			return err
		}
		serial, err := st.nextSerial(o.randSerial)
		if err != nil {
			return err
		}
		usage, err := parseKeyUsage(o.keyUsage)
		if err != nil {
			return err
		}
		extUsage, err := parseExtKeyUsage(o.extKeyUsage)
		if err != nil {
			return err
		}
		sig, err := signatureAlgorithm(o.digest, parentKey)
		if err != nil {
			return err
		}
		now := time.Now()
		tmpl := &x509.Certificate{
			SerialNumber:       serial,
			Subject:            parseSubject(o.subject),
			NotBefore:          now,
			NotAfter:           now.AddDate(0, 0, o.days),
			KeyUsage:           usage,
			ExtKeyUsage:        extUsage,
			SignatureAlgorithm: sig,
		}
		if err := applyCAOptions(tmpl, &o.caOptions, keySigner.Public()); err != nil {
			return err
		}
		if o.authorityKeyID {
			tmpl.AuthorityKeyId = parentCert.SubjectKeyId
		} else {
			// Prevent the stdlib from deriving an authority key identifier.
			parentCert.SubjectKeyId = nil
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, keySigner.Public(), parentKey)
		if err != nil {
			return err
		}
		cerPEM := encodeCert(der)
		if err := writeFile(certPath, cerPEM, 0644); err != nil {
			return err
		}
		parentPEM, err := os.ReadFile(o.cert)
		if err != nil {
			return err
		}
		if err := writeFile(filepath.Join(o.dir, "chain.cer"), append(cerPEM, parentPEM...), 0644); err != nil {
			return err
		}
		if err := st.record(serial, tmpl.Subject.String(), "inte", "InteCA", certPath, keyPath, now, tmpl.NotAfter); err != nil {
			return err
		}
	}

	if exists(keyPath) && exists(certPath) {
		info("Done.\n")
	}
	return nil
}

type certOptions struct {
	keyOptions
	dir        string
	cert       string
	key        string
	chain      string
	domains    []string
	randSerial bool
}

func newCertCmd() *cobra.Command {
	o := &certOptions{}
	cmd := &cobra.Command{
		Use:           "cert",
		Aliases:       []string{"sign"},
		Short:         "Create Domain Name Certificate",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCert(o)
		},
	}
	addKeyFlags(cmd, &o.keyOptions, keyOptions{cipher: "ecc", bits: 3072, subject: defaultCertSubject, days: 90})
	f := cmd.Flags()
	f.StringVarP(&o.dir, "dir", "D", ".", "certificate directory")
	f.StringVarP(&o.cert, "cert", "c", "", "signing certificate")
	f.StringVarP(&o.key, "key", "k", "", "signing certificate key")
	f.StringVar(&o.chain, "chain", "", "certificate chain")
	f.StringArrayVarP(&o.domains, "domain", "d", nil, "domain name")
	f.BoolVarP(&o.randSerial, "random-serial", "R", false, "use a random serial number")
	cmd.SetHelpFunc(func(cmd *cobra.Command, args []string) { helpWithCertCommand() })
	return cmd
}

func runCert(o *certOptions) error {
	if o.cert == "" {
		o.cert = filepath.Join(o.dir, "InteCA.cer")
	}
	if o.key == "" {
		o.key = filepath.Join(o.dir, "InteCA.key")
	}
	if o.chain == "" {
		o.chain = filepath.Join(o.dir, "chain.cer")
	}
	name := parseSubject(o.subject)
	cn := name.CommonName
	if len(o.domains) >= 1 {
		cn = o.domains[0]
	}
	if cn == "" {
		return fmt.Errorf("common name is empty, set --domain or --subject")
	}

	info("Refresh Database\n")
	info("Start generating certificate\n")

	st, err := openStore(filepath.Join(o.dir, dbFileName))
	if err != nil {
		return err
	}
	defer st.close()

	domainDir := filepath.Join(o.dir, "certs", cn+"_"+o.cipher)
	if err := os.MkdirAll(domainDir, 0755); err != nil {
		return err
	}
	fullchainPath := filepath.Join(domainDir, "fullchain.cer")
	if exists(fullchainPath) {
		warn("Certificate for domain name %s already exist\n", cn)
		return nil
	}

	keyPath := filepath.Join(domainDir, cn+".key")
	if !exists(keyPath) {
		_, keyPEM, err := generateKey(o.cipher, o.bits)
		if err != nil {
			return err
		}
		if err := writeFile(keyPath, keyPEM, 0600); err != nil {
			return err
		}
	}
	keySigner, err := loadKey(keyPath)
	if err != nil {
		return err
	}

	csrPath := filepath.Join(domainDir, cn+".csr")
	if !exists(csrPath) {
		der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: name}, keySigner)
		if err != nil {
			return err
		}
		if err := writeFile(csrPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), 0644); err != nil {
			return err
		}
	}

	cerPath := filepath.Join(domainDir, cn+".cer")
	if exists(csrPath) && exists(keyPath) && !exists(cerPath) {
		parentCert, err := loadCert(o.cert)
		if err != nil {
			return err
		}
		parentKey, err := loadKey(o.key)
		if err != nil {
			return err
		}
		serial, err := st.nextSerial(o.randSerial)
		if err != nil {
			return err
		}
		now := time.Now()
		tmpl := &x509.Certificate{
			SerialNumber:          serial,
			Subject:               name,
			NotBefore:             now,
			NotAfter:              now.AddDate(0, 0, o.days),
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			BasicConstraintsValid: true,
			AuthorityKeyId:        parentCert.SubjectKeyId,
			SignatureAlgorithm:    sigAlg(parentKey),
		}
		if len(o.domains) > 1 {
			tmpl.DNSNames = append(tmpl.DNSNames, o.domains...)
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, keySigner.Public(), parentKey)
		if err != nil {
			return err
		}
		cerPEM := encodeCert(der)
		if err := writeFile(cerPath, cerPEM, 0644); err != nil {
			return err
		}
		fullchain := cerPEM
		if exists(o.chain) {
			chainPEM, err := os.ReadFile(o.chain)
			if err != nil {
				return err
			}
			fullchain = append(fullchain, chainPEM...)
		}
		if err := writeFile(fullchainPath, fullchain, 0644); err != nil {
			return err
		}
		if err := st.record(serial, name.String(), "cert", cn, cerPath, keyPath, now, tmpl.NotAfter); err != nil {
			return err
		}
	}

	if exists(keyPath) && exists(cerPath) && exists(fullchainPath) {
		info("Done.\n")
	}
	return nil
}

func newRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:           progName,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.ArbitraryArgs,
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("Use \"%s help\" to view the help text", cmd.Name())
			}
			return fmt.Errorf("Unknown subcommand %s, use \"%s help\" for help", args[0], cmd.Name())
		},
	}
	root.SetHelpFunc(func(cmd *cobra.Command, args []string) { helpCommand() })
	root.AddCommand(newRootCmd(), newInteCmd(), newCertCmd(), newDBCmd())
	return root
}

func helpCommand() {
	fmt.Printf(`Usage: %s SubCommand

SubCommand:
	root  Create a root certificate
	inte  Create Intermediate Certificate
	cert  Create Domain Name Certificate
	sign  Same as cert
	db    Manage the certificate database
	help  Show this help text
`, progName)
}

func helpWithRootCommand() {
	fmt.Printf(`Usage: %s root Options

Options:
	-h, --help          Show this help text
	-C, --cipher        Set the encryption method used when generating the private key(Default: ecc)
	--rsa-bits          Set the key length when generating the RSA private key(Default: 3072)
	-s, --subject       Set subject information(Default: "/C=CN/O=Test SSL/CN=Test SSL CA")
	--days              Set the expiration time(Default: 3650)
	-D, --dir           Set the file save directory(Default: .)
	--key-usage         Set key usage extension, comma separated(Default: empty)
	--ext-key-usage     Set extended key usage extension, comma separated(Default: empty)
	--path-length       Set CA path length, -1 for unset(Default: -1)
	--digest            Set signature digest algorithm(Default: sha512)
	--subject-key-id    Include subject key identifier(Default: true)
	--authority-key-id  Include authority key identifier(Default: true)
`, progName)
}

func helpWithInteCommand() {
	fmt.Printf(`Usage: %s inte Options

Options:
	-h, --help          Show this help text
	-C, --cipher        Set the encryption method used when generating the private key(Default: ecc)
	--rsa-bits          Set the key length when generating the RSA private key(Default: 3072)
	-s, --subject       Set subject information(Default: "/C=CN/O=Test SSL/CN=Test Inte CA")
	--days              Set the expiration time(Default: 1825)
	-D, --dir           Set the file save directory(Default: .)
	-c, --cert          Set intermediate certificate
	-k, --key           Set intermediate certificate key
	-R, --random-serial Use a random serial number
	--key-usage         Set key usage extension, comma separated(Default: "keyCertSign,cRLSign")
	--ext-key-usage     Set extended key usage extension, comma separated(Default: "serverAuth,clientAuth")
	--path-length       Set CA path length, -1 for unset(Default: 0)
	--digest            Set signature digest algorithm(Default: sha512)
	--subject-key-id    Include subject key identifier(Default: true)
	--authority-key-id  Include authority key identifier(Default: true)
`, progName)
}

func helpWithCertCommand() {
	fmt.Printf(`Usage: %s cert|sign Options

Options:
	-h, --help          Show this help text
	-C, --cipher        Set the encryption method used when generating the private key(Default: ecc)
	--rsa-bits          Set the key length when generating the RSA private key(Default: 3072)
	-s, --subject       Set subject information(Default: "/C=CN")
	--days              Set the expiration time(Default: 90)
	-D, --dir           Set up the certificate directory(Default: .)
	-c, --cert          Set certificate(Default: <dir>/InteCA.cer)
	-k, --key           Set certificate key(Default: <dir>/InteCA.key)
	--chain             Set up a certificate chain(Default: <dir>/chain.cer)
	-d, --domain        Set a domain name, repeatable
	-R, --random-serial Use a random serial number
`, progName)
}

func main() {
	if err := newRootCommand().Execute(); err != nil {
		erro("%s\n", err)
		os.Exit(1)
	}
}
