package main

import (
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
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
		domains          []string
		sequentialSerial bool
	)
	cmd := &cobra.Command{
		Use:           "cert",
		Aliases:       []string{"sign"},
		Short:         "Create Domain Name Certificate",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCert(&keyOptions, dir, certFile, keyFile, chainFile, domains, sequentialSerial)
		},
	}
	addKeyFlags(cmd, &keyOptions, option.KeyOptions{Cipher: "ecc", Bits: 3072, Subject: defaultCertSubject, Days: 90})
	flags := cmd.Flags()
	flags.StringVarP(&dir, "dir", "D", ".", "certificate directory")
	flags.StringVarP(&certFile, "cert", "c", "", "signing certificate")
	flags.StringVarP(&keyFile, "key", "k", "", "signing certificate key")
	flags.StringVar(&chainFile, "chain", "", "certificate chain")
	flags.StringArrayVarP(&domains, "domain", "d", nil, "domain name")
	flags.BoolVar(&sequentialSerial, "sequential-serial", false, "use the sequential database serial number instead of a random one")
	return cmd
}

func runCert(keyOptions *option.KeyOptions, dir, certFile, keyFile, chainFile string, domains []string, sequentialSerial bool) error {
	if certFile == "" {
		certFile = filepath.Join(dir, "InteCA.cer")
	}
	if keyFile == "" {
		keyFile = filepath.Join(dir, "InteCA.key")
	}
	if chainFile == "" {
		chainFile = filepath.Join(dir, "chain.cer")
	}

	name := pki.ParseSubject(keyOptions.Subject)
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
		return fmt.Errorf("common name is empty, set --domain or --subject")
	}
	if len(dnsNames) == 0 {
		dnsNames = append(dnsNames, cn)
	}
	if name.CommonName != "" && !containsString(dnsNames, name.CommonName) {
		dnsNames = append(dnsNames, name.CommonName)
	}

	log.Info("Refresh Database\n")
	log.Info("Start generating certificate\n")

	st, err := store.Open(filepath.Join(dir, store.FileName))
	if err != nil {
		return err
	}
	defer st.Close()

	domainDir := filepath.Join(dir, "certs", cn+"_"+keyOptions.Cipher)
	if err := os.MkdirAll(domainDir, 0755); err != nil {
		return err
	}
	fullchainPath := filepath.Join(domainDir, "fullchain.cer")
	if exists(fullchainPath) {
		log.Warn("Certificate for domain name %s already exist\n", cn)
		return nil
	}

	keyPath := filepath.Join(domainDir, cn+".key")
	keySigner, err := pki.EnsureKey(keyPath, keyOptions.Cipher, keyOptions.Bits)
	if err != nil {
		return err
	}
	if err := pki.EnsureCSR(filepath.Join(domainDir, cn+".csr"), name, keySigner); err != nil {
		return err
	}

	cerPath := filepath.Join(domainDir, cn+".cer")
	if !exists(cerPath) {
		parentCert, err := pki.LoadCert(certFile)
		if err != nil {
			return err
		}
		parentKey, err := pki.LoadKey(keyFile)
		if err != nil {
			return err
		}
		serial, err := nextSerial(st, sequentialSerial)
		if err != nil {
			return err
		}
		now := time.Now()
		cert, der, err := pki.Issue(keySigner.Public(), keySigner, parentCert, parentKey, pki.IssueOptions{
			Serial:         serial,
			Subject:        name,
			NotBefore:      now,
			NotAfter:       pki.ValidUntil(parentCert, keyOptions.Days, now),
			KeyUsage:       pki.LeafKeyUsage(keySigner),
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
		if exists(chainFile) {
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

	if exists(keyPath) && exists(cerPath) && exists(fullchainPath) {
		log.Info("Done.\n")
	}
	return nil
}
