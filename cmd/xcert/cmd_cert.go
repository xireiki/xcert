package main

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"xcert/log"
	"xcert/option"
	"xcert/pki"
	"xcert/store"

	"github.com/spf13/cobra"
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
			return runCert(&keyOptions, dir, certFile, keyFile, chainFile, csrFile, domains, sequentialSerial)
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
	flags.BoolVar(&sequentialSerial, "sequential-serial", false, "use the sequential database serial number instead of a random one")
	return cmd
}

func validateCommonName(cn string) error {
	if cn == "" {
		return fmt.Errorf("common name is empty")
	}
	if cn == "." || cn == ".." || cn != filepath.Base(cn) || strings.ContainsAny(cn, `/\`) || strings.ContainsRune(cn, 0) {
		return fmt.Errorf("unsafe common name %q", cn)
	}
	return nil
}

func resolveNames(name pkix.Name, domains []string) (pkix.Name, string, []string, error) {
	cn := name.CommonName
	var dnsNames []string
	if len(domains) >= 1 {
		cn = domains[0]
		dnsNames = append(dnsNames, domains...)
		if name.CommonName == "" {
			name.CommonName = cn
		}
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
	if name.CommonName != "" && !containsString(dnsNames, name.CommonName) {
		dnsNames = append(dnsNames, name.CommonName)
	}
	return name, cn, dnsNames, nil
}

func runCert(keyOptions *option.KeyOptions, dir, certFile, keyFile, chainFile, csrFile string, domains []string, sequentialSerial bool) error {
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
		csrDomains := domains
		if len(csrDomains) == 0 {
			csrDomains = csr.DNSNames
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

	st, err := store.Open(filepath.Join(dir, store.FileName))
	if err != nil {
		return err
	}
	defer st.Close()

	domainDir := filepath.Join(dir, "certs", cn+"_"+cipher)
	if err := os.MkdirAll(domainDir, 0755); err != nil {
		return err
	}
	fullchainPath := filepath.Join(domainDir, "fullchain.cer")
	if pki.Exists(fullchainPath) {
		log.Warn("Certificate for domain name %s already exist\n", cn)
		return nil
	}

	cerPath := filepath.Join(domainDir, cn+".cer")
	var parentCert *x509.Certificate
	var parentKey crypto.Signer
	if !pki.Exists(cerPath) {
		parentCert, err = pki.LoadCert(certFile)
		if err != nil {
			return err
		}
		if err := pki.ValidateCA(parentCert); err != nil {
			return fmt.Errorf("%s: %w", certFile, err)
		}
		parentKey, err = pki.LoadKey(keyFile)
		if err != nil {
			return err
		}
	}

	keyPath := ""
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
		keyPath = filepath.Join(domainDir, cn+".key")
		keySigner, err = pki.EnsureKey(keyPath, keyOptions.Cipher, keyOptions.Bits)
		if err != nil {
			return err
		}
		if err := pki.EnsureCSR(csrPath, name, dnsNames, keySigner); err != nil {
			return err
		}
		publicKey = keySigner.Public()
	}

	if !pki.Exists(cerPath) {
		serial, err := nextSerial(st, sequentialSerial)
		if err != nil {
			return err
		}
		now := time.Now()
		cert, der, err := pki.Issue(publicKey, parentCert, parentKey, pki.IssueOptions{
			Serial:         serial,
			Subject:        name,
			NotBefore:      now.Add(-time.Minute),
			NotAfter:       pki.ValidUntil(parentCert, keyOptions.Days, now),
			KeyUsage:       pki.LeafKeyUsage(publicKey),
			ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
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
		if err := st.Record(serial, cert.Subject.String(), "cert", cn, cerPath, keyPath, now, cert.NotAfter); err != nil {
			return err
		}
	}

	done := pki.Exists(cerPath) && pki.Exists(fullchainPath)
	if !externalCSR {
		done = done && pki.Exists(keyPath)
	}
	if done {
		log.Info("Done.\n")
	}
	return nil
}
