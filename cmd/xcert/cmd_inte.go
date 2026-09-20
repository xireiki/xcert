package main

import (
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

func newInteCommand() *cobra.Command {
	var (
		keyOptions       option.KeyOptions
		caOptions        option.CAOptions
		dir              string
		certFile         string
		keyFile          string
		sequentialSerial bool
	)
	cmd := &cobra.Command{
		Use:           "inte",
		Short:         "Create Intermediate Certificate",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if cmd.Flags().NFlag() == 0 && len(args) == 0 {
				return cmd.Help()
			}
			return runInte(&keyOptions, &caOptions, dir, certFile, keyFile, sequentialSerial)
		},
	}
	addKeyFlags(cmd, &keyOptions, option.KeyOptions{Cipher: "ecc", Bits: 3072, Subject: defaultInteSubject, Days: 1825})
	addCAFlags(cmd, &caOptions, option.CAOptions{KeyUsage: []string{"keyCertSign", "cRLSign"}, ExtKeyUsage: []string{"serverAuth", "clientAuth"}, PathLength: 0, Digest: "sha512", SubjectKeyID: true, AuthorityKeyID: true})
	flags := cmd.Flags()
	flags.StringVarP(&dir, "dir", "D", ".", "certificate directory")
	flags.StringVarP(&certFile, "cert", "c", "", "parent CA certificate")
	flags.StringVarP(&keyFile, "key", "k", "", "parent CA private key")
	flags.BoolVar(&sequentialSerial, "sequential-serial", false, "use the sequential database serial number instead of a random one")
	return cmd
}

func runInte(keyOptions *option.KeyOptions, caOptions *option.CAOptions, dir, certFile, keyFile string, sequentialSerial bool) error {
	certPath := filepath.Join(dir, "InteCA.cer")
	if exists(certPath) {
		log.Warn("Intermediate certificate already exists\n")
		return nil
	}
	if certFile == "" || keyFile == "" {
		return fmt.Errorf("intermediate CA requires -c/--cert and -k/--key")
	}
	if !exists(certFile) {
		return fmt.Errorf("certificate not found: %s", certFile)
	}
	if !exists(keyFile) {
		return fmt.Errorf("key not found: %s", keyFile)
	}
	for _, name := range []string{"newcerts", "crl", "certs"} {
		if err := os.MkdirAll(filepath.Join(dir, name), 0755); err != nil {
			return err
		}
	}

	st, err := store.Open(filepath.Join(dir, store.FileName))
	if err != nil {
		return err
	}
	defer st.Close()
	log.Info("Refresh Database\n")
	log.Info("Start generating certificate\n")

	keyPath := filepath.Join(dir, "InteCA.key")
	keySigner, err := pki.EnsureKey(keyPath, keyOptions.Cipher, keyOptions.Bits)
	if err != nil {
		return err
	}
	subject := pki.ParseSubject(keyOptions.Subject)
	if err := pki.EnsureCSR(filepath.Join(dir, "InteCA.csr"), subject, keySigner); err != nil {
		return err
	}
	parentCert, err := pki.LoadCert(certFile)
	if err != nil {
		return err
	}
	if err := pki.ValidateCA(parentCert); err != nil {
		return fmt.Errorf("%s: %w", certFile, err)
	}
	parentKey, err := pki.LoadKey(keyFile)
	if err != nil {
		return err
	}
	usage, err := pki.ParseKeyUsage(caOptions.KeyUsage)
	if err != nil {
		return err
	}
	extUsage, err := pki.ParseExtKeyUsage(caOptions.ExtKeyUsage)
	if err != nil {
		return err
	}

	serial, err := nextSerial(st, sequentialSerial)
	if err != nil {
		return err
	}
	now := time.Now()
	cert, der, err := pki.Issue(keySigner.Public(), parentCert, parentKey, pki.IssueOptions{
		Serial:         serial,
		Subject:        subject,
		NotBefore:      now.Add(-time.Minute),
		NotAfter:       pki.ValidUntil(parentCert, keyOptions.Days, now),
		KeyUsage:       usage,
		ExtKeyUsage:    extUsage,
		IsCA:           true,
		PathLength:     caOptions.PathLength,
		SubjectKeyID:   caOptions.SubjectKeyID,
		AuthorityKeyID: caOptions.AuthorityKeyID,
		Digest:         caOptions.Digest,
	})
	if err != nil {
		return err
	}
	cerPEM := pki.EncodeCert(der)
	if err := pki.WriteFile(certPath, cerPEM, 0644); err != nil {
		return err
	}
	parentPEM, err := os.ReadFile(certFile)
	if err != nil {
		return err
	}
	if err := pki.WriteFile(filepath.Join(dir, "chain.cer"), append(cerPEM, parentPEM...), 0644); err != nil {
		return err
	}
	if err := st.Record(serial, cert.Subject.String(), "inte", "InteCA", certPath, keyPath, now, cert.NotAfter); err != nil {
		return err
	}

	log.Info("Done.\n")
	return nil
}
