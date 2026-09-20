package main

import (
	"os"
	"path/filepath"
	"time"

	"xcert/log"
	"xcert/option"
	"xcert/pki"

	"github.com/spf13/cobra"
)

func newRootCommand() *cobra.Command {
	var (
		keyOptions option.KeyOptions
		caOptions  option.CAOptions
		dir        string
	)
	cmd := &cobra.Command{
		Use:           "root",
		Short:         "Create a root certificate",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if cmd.Flags().NFlag() == 0 && len(args) == 0 {
				return cmd.Help()
			}
			return runRoot(&keyOptions, &caOptions, dir)
		},
	}
	addKeyFlags(cmd, &keyOptions, option.KeyOptions{Cipher: "ecc", Bits: 3072, Subject: defaultRootSubject, Days: 3650})
	addCAFlags(cmd, &caOptions, option.CAOptions{KeyUsage: []string{"keyCertSign", "cRLSign"}, PathLength: -1, Digest: "sha512", SubjectKeyID: true, AuthorityKeyID: true})
	cmd.Flags().StringVarP(&dir, "dir", "D", ".", "certificate directory")
	return cmd
}

func runRoot(keyOptions *option.KeyOptions, caOptions *option.CAOptions, dir string) error {
	if err := validateDays("--days", keyOptions.Days); err != nil {
		return err
	}
	certPath := filepath.Join(dir, "RootCA.cer")
	if pki.Exists(certPath) {
		log.Warn("Root certificate already exists\n")
		return nil
	}
	for _, name := range []string{"newcerts", "crl"} {
		if err := os.MkdirAll(filepath.Join(dir, name), 0755); err != nil {
			return err
		}
	}

	keyPath := filepath.Join(dir, "RootCA.key")
	key, err := pki.EnsureKey(keyPath, keyOptions.Cipher, keyOptions.Bits)
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
	serial, err := pki.RandomSerial()
	if err != nil {
		return err
	}

	now := time.Now()
	cert, der, err := pki.IssueSelfSigned(key, pki.IssueOptions{
		Serial:         serial,
		Subject:        pki.ParseSubject(keyOptions.Subject),
		NotBefore:      now.Add(-time.Minute),
		NotAfter:       now.AddDate(0, 0, keyOptions.Days),
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
	st, err := openStore(dir)
	if err != nil {
		return err
	}
	defer st.Close()

	if err := pki.WriteFile(certPath, pki.EncodeCert(der), 0644); err != nil {
		return err
	}
	if err := st.Record(serial, cert.Subject.String(), "root", "RootCA", certPath, keyPath, cert.NotBefore, cert.NotAfter); err != nil {
		os.Remove(certPath)
		return err
	}

	log.Info("Done.\n")
	return nil
}
