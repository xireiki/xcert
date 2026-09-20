package main

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/xireiki/xcert/log"
	"github.com/xireiki/xcert/option"
	"github.com/xireiki/xcert/pki"

	"github.com/spf13/cobra"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func newCertCommand() *cobra.Command {
	var (
		keyOptions       option.KeyOptions
		dir              string
		certFile         string
		keyFile          string
		chainFile        string
		csrFile          string
		domains          []string
		extKeyUsage      []string
		codeSigning      bool
		pfxPassword      string
		sequentialSerial bool
	)
	cmd := &cobra.Command{
		Use:           "cert",
		Short:         "Create Domain Name Certificate",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if cmd.Flags().NFlag() == 0 && len(args) == 0 {
				return cmd.Help()
			}
			if codeSigning && cmd.Flags().Changed("ext-key-usage") {
				return fmt.Errorf("--code-signing and --ext-key-usage are mutually exclusive")
			}
			if codeSigning && !cmd.Flags().Changed("days") {
				keyOptions.Days = 365
			}
			return runCert(&keyOptions, dir, certFile, keyFile, chainFile, csrFile, domains, extKeyUsage, codeSigning, pfxPassword, sequentialSerial)
		},
	}
	addKeyFlags(cmd, &keyOptions, option.KeyOptions{Cipher: "ecc", Bits: 3072, Subject: defaultCertSubject, Days: 90})
	flags := cmd.Flags()
	flags.StringVarP(&dir, "dir", "D", ".", "certificate directory")
	flags.StringVarP(&certFile, "cert", "c", "", "signing certificate")
	flags.StringVarP(&keyFile, "key", "k", "", "signing certificate key")
	flags.StringVar(&chainFile, "chain", "", "certificate chain")
	flags.StringVar(&csrFile, "csr", "", "sign an existing certificate request instead of generating a key")
	flags.StringArrayVarP(&domains, "domain", "d", nil, "domain name")
	flags.StringSliceVar(&extKeyUsage, "ext-key-usage", []string{"serverAuth", "clientAuth"}, "extended key usage extension (comma separated)")
	flags.BoolVar(&codeSigning, "code-signing", false, "issue a Windows code signing certificate (extended key usage codeSigning)")
	flags.StringVar(&pfxPassword, "pfx-password", "", "password for the generated .pfx file (only with --code-signing)")
	flags.BoolVar(&sequentialSerial, "sequential-serial", false, "use the sequential database serial number instead of a random one")
	return cmd
}

func validateCommonName(cn string) error {
	if cn == "" {
		return fmt.Errorf("common name is empty")
	}
	if cn == "." || cn == ".." || cn != filepath.Base(cn) || strings.ContainsAny(cn, `/\`) || strings.IndexFunc(cn, unicode.IsControl) >= 0 {
		return fmt.Errorf("unsafe common name %q", cn)
	}
	return nil
}

func resolveNames(name pkix.Name, domains []string) (pkix.Name, string, []string, error) {
	cn := name.CommonName
	var dnsNames []string
	if len(domains) >= 1 {
		cn = domains[0]
		name.CommonName = cn
		dnsNames = append(dnsNames, domains...)
	}
	if cn == "" {
		return name, "", nil, fmt.Errorf("common name is empty, set --domain or --subject")
	}
	if err := validateCommonName(cn); err != nil {
		return name, "", nil, err
	}
	if len(dnsNames) == 0 {
		dnsNames = append(dnsNames, cn)
	}
	return name, cn, dnsNames, nil
}

func runCert(keyOptions *option.KeyOptions, dir, certFile, keyFile, chainFile, csrFile string, domains, extKeyUsage []string, codeSigning bool, pfxPassword string, sequentialSerial bool) error {
	if err := validateDays("--days", keyOptions.Days); err != nil {
		return err
	}
	if codeSigning && csrFile != "" {
		return fmt.Errorf("--code-signing requires a private key and cannot sign an external request")
	}
	var extUsages []x509.ExtKeyUsage
	if codeSigning {
		extUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
	} else {
		var err error
		extUsages, err = pki.ParseExtKeyUsage(extKeyUsage)
		if err != nil {
			return err
		}
	}
	if certFile == "" {
		certFile = filepath.Join(dir, "InteCA.cer")
	}
	if keyFile == "" {
		keyFile = filepath.Join(dir, "InteCA.key")
	}
	if chainFile == "" {
		chainFile = filepath.Join(dir, "chain.cer")
	}

	var (
		name        pkix.Name
		cn          string
		dnsNames    []string
		cipher      string
		publicKey   crypto.PublicKey
		keySigner   crypto.Signer
		externalCSR = csrFile != ""
	)
	if externalCSR {
		csr, err := pki.LoadCSR(csrFile)
		if err != nil {
			return err
		}
		csrDomains := append([]string{}, domains...)
		for _, domain := range csr.DNSNames {
			if !containsString(csrDomains, domain) {
				csrDomains = append(csrDomains, domain)
			}
		}
		name, cn, dnsNames, err = resolveNames(csr.Subject, csrDomains)
		if err != nil {
			return err
		}
		publicKey = csr.PublicKey
		cipher = pki.KeyCipher(publicKey)
	} else {
		var err error
		name, cn, dnsNames, err = resolveNames(pki.ParseSubject(keyOptions.Subject), domains)
		if err != nil {
			return err
		}
		cipher = keyOptions.Cipher
		if err := pki.ValidateCipher(cipher); err != nil {
			return err
		}
	}

	log.Info("Start generating certificate\n")

	st, err := openStore(dir)
	if err != nil {
		return err
	}
	defer st.Close()

	domainDir := filepath.Join(dir, "certs", cn+"_"+cipher)
	if err := os.MkdirAll(domainDir, 0755); err != nil {
		return err
	}
	fullchainPath := filepath.Join(domainDir, "fullchain.cer")
	pfxPath := filepath.Join(domainDir, cn+".pfx")
	artifactPath := fullchainPath
	if codeSigning {
		artifactPath = pfxPath
	}
	if pki.Exists(artifactPath) {
		log.Warn("Certificate for domain name %s already exist\n", cn)
		return nil
	}

	cerPath := filepath.Join(domainDir, cn+".cer")
	var parentCert *x509.Certificate
	var parentKey crypto.Signer
	keyPath := ""
	if !externalCSR {
		keyPath = filepath.Join(domainDir, cn+".key")
	}

	if !pki.Exists(cerPath) {
		parentCert, err = pki.LoadCert(certFile)
		if err != nil {
			return err
		}
		if err := pki.ValidateCA(parentCert); err != nil {
			return fmt.Errorf("%s: %w", certFile, err)
		}
		if codeSigning && !pki.AllowsExtKeyUsage(parentCert, x509.ExtKeyUsageCodeSigning) {
			return fmt.Errorf("%s does not permit code signing", certFile)
		}
		parentKey, err = pki.LoadKey(keyFile)
		if err != nil {
			return err
		}

		csrPath := filepath.Join(domainDir, cn+".csr")
		if externalCSR {
			csrPEM, err := os.ReadFile(csrFile)
			if err != nil {
				return err
			}
			if err := pki.WriteFile(csrPath, csrPEM, 0644); err != nil {
				return err
			}
		} else {
			keySigner, err = pki.EnsureKey(keyPath, keyOptions.Cipher, keyOptions.Bits)
			if err != nil {
				return err
			}
			if err := pki.EnsureCSR(csrPath, name, dnsNames, keySigner); err != nil {
				return err
			}
			publicKey = keySigner.Public()
		}

		serial, err := nextSerial(st, sequentialSerial)
		if err != nil {
			return err
		}
		now := time.Now()
		keyUsage := pki.LeafKeyUsage(publicKey)
		if codeSigning {
			keyUsage = x509.KeyUsageDigitalSignature
		}
		cert, der, err := pki.Issue(publicKey, parentCert, parentKey, pki.IssueOptions{
			Serial:         serial,
			Subject:        name,
			NotBefore:      now.Add(-time.Minute),
			NotAfter:       pki.ValidUntil(parentCert, keyOptions.Days, now),
			KeyUsage:       keyUsage,
			ExtKeyUsage:    extUsages,
			DNSNames:       dnsNames,
			IsCA:           false,
			AuthorityKeyID: true,
			Digest:         "sha256",
		})
		if err != nil {
			return err
		}
		cerPEM := pki.EncodeCert(der)
		if err := pki.WriteFile(cerPath, cerPEM, 0644); err != nil {
			return err
		}
		if err := st.Record(serial, cert.Subject.String(), "cert", cn, cerPath, keyPath, cert.NotBefore, cert.NotAfter); err != nil {
			os.Remove(cerPath)
			return err
		}
	}

	if codeSigning {
		if !pki.Exists(pfxPath) {
			leaf, err := pki.LoadCert(cerPath)
			if err != nil {
				return err
			}
			signer, err := pki.LoadKey(keyPath)
			if err != nil {
				return err
			}
			caCerts, err := loadChain(chainFile)
			if err != nil {
				return err
			}
			data, err := pkcs12.Modern2023.Encode(signer, leaf, caCerts, pfxPassword)
			if err != nil {
				return err
			}
			if err := pki.WriteFile(pfxPath, data, 0600); err != nil {
				return err
			}
		}
	} else if !pki.Exists(fullchainPath) {
		cerPEM, err := os.ReadFile(cerPath)
		if err != nil {
			return err
		}
		fullchain := cerPEM
		if pki.Exists(chainFile) {
			chainPEM, err := os.ReadFile(chainFile)
			if err != nil {
				return err
			}
			fullchain = append(fullchain, chainPEM...)
		}
		if err := pki.WriteFile(fullchainPath, fullchain, 0644); err != nil {
			return err
		}
	}

	done := pki.Exists(cerPath) && pki.Exists(artifactPath)
	if !externalCSR {
		done = done && pki.Exists(keyPath)
	}
	if done {
		log.Info("Done.\n")
	}
	return nil
}

func loadChain(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var certs []*x509.Certificate
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
}
