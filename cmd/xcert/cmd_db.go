package main

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"xcert/log"
	"xcert/option"
	"xcert/pki"
	"xcert/store"

	"github.com/spf13/cobra"
)

func newDBCommand() *cobra.Command {
	var dir string
	cmd := &cobra.Command{
		Use:           "db",
		Short:         "Manage the certificate database",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.PersistentFlags().StringVarP(&dir, "dir", "D", ".", "certificate directory")
	cmd.AddCommand(
		newDBListCommand(&dir),
		newDBShowCommand(&dir),
		newDBDeleteCommand(&dir),
		newDBRevokeCommand(&dir),
		newDBUnrevokeCommand(&dir),
	)
	return cmd
}

func openDB(dir string) (*store.Store, error) {
	return store.Open(filepath.Join(dir, store.FileName))
}

func newDBListCommand(dir *string) *cobra.Command {
	return &cobra.Command{
		Use:           "list",
		Short:         "List all records",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := openDB(*dir)
			if err != nil {
				return err
			}
			defer st.Close()
			records, err := st.List()
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "SERIAL\tTYPE\tNAME\tSTATUS\tNOT_AFTER")
			for _, record := range records {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", record.Serial, record.Type, record.Name, record.Status, record.NotAfter)
			}
			return w.Flush()
		},
	}
}

func newDBShowCommand(dir *string) *cobra.Command {
	return &cobra.Command{
		Use:           "show <serial|name>",
		Short:         "Show a record",
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := openDB(*dir)
			if err != nil {
				return err
			}
			defer st.Close()
			record, err := st.Resolve(args[0])
			if err != nil {
				return err
			}
			revoked := ""
			if record.RevokedAt.Valid {
				revoked = record.RevokedAt.String
			}
			fmt.Fprintf(cmd.OutOrStdout(), `Serial:    %s
Type:      %s
Name:      %s
Subject:   %s
Status:    %s
NotBefore: %s
NotAfter:  %s
Cert:      %s
Key:       %s
Created:   %s
Revoked:   %s
`, record.Serial, record.Type, record.Name, record.Subject, record.Status, record.NotBefore, record.NotAfter, record.CertPath, record.KeyPath, record.CreatedAt, revoked)
			return nil
		},
	}
}

func newDBDeleteCommand(dir *string) *cobra.Command {
	return &cobra.Command{
		Use:           "delete <serial|name>",
		Short:         "Delete a record",
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := openDB(*dir)
			if err != nil {
				return err
			}
			defer st.Close()
			record, err := st.Delete(args[0])
			if err != nil {
				return err
			}
			log.Info("Deleted %s (%s)\n", record.Serial, record.Name)
			return nil
		},
	}
}

func addCRLFlags(cmd *cobra.Command, o *option.CRLOptions) {
	flags := cmd.Flags()
	flags.StringVar(&o.CACert, "ca-cert", "", "CA certificate used to sign the CRL")
	flags.StringVar(&o.CAKey, "ca-key", "", "CA private key used to sign the CRL")
	flags.StringVar(&o.CRL, "crl", "", "output CRL file")
	flags.IntVar(&o.Days, "crl-days", 30, "CRL validity in days")
}

func newDBRevokeCommand(dir *string) *cobra.Command {
	var crlOptions option.CRLOptions
	cmd := &cobra.Command{
		Use:           "revoke <serial|name>",
		Short:         "Revoke a certificate and update the CRL",
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSetStatus(*dir, args[0], "R", &crlOptions)
		},
	}
	addCRLFlags(cmd, &crlOptions)
	return cmd
}

func newDBUnrevokeCommand(dir *string) *cobra.Command {
	var crlOptions option.CRLOptions
	cmd := &cobra.Command{
		Use:           "unrevoke <serial|name>",
		Short:         "Unrevoke a certificate and update the CRL",
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSetStatus(*dir, args[0], "V", &crlOptions)
		},
	}
	addCRLFlags(cmd, &crlOptions)
	return cmd
}

func runSetStatus(dir, selector, status string, crlOptions *option.CRLOptions) error {
	st, err := openDB(dir)
	if err != nil {
		return err
	}
	defer st.Close()

	original, err := st.Resolve(selector)
	if err != nil {
		return err
	}
	record, err := st.SetStatus(selector, status)
	if err != nil {
		return err
	}
	verb := "Revoked"
	if status == "V" {
		verb = "Unrevoked"
	}
	log.Info("%s %s (%s)\n", verb, record.Serial, record.Name)

	if err := writeCRL(dir, crlOptions, st); err != nil {
		if restoreErr := st.Restore(original); restoreErr != nil {
			return fmt.Errorf("CRL update failed: %w (status could not be restored: %v)", err, restoreErr)
		}
		return fmt.Errorf("CRL update failed, status restored: %w", err)
	}
	return nil
}

func writeCRL(dir string, o *option.CRLOptions, st *store.Store) error {
	if err := validateDays("--crl-days", o.Days); err != nil {
		return err
	}
	caCert := o.CACert
	if caCert == "" {
		caCert = filepath.Join(dir, "InteCA.cer")
	}
	caKey := o.CAKey
	if caKey == "" {
		caKey = filepath.Join(dir, "InteCA.key")
	}
	crlPath := o.CRL
	if crlPath == "" {
		base := strings.TrimSuffix(filepath.Base(caCert), filepath.Ext(caCert))
		crlPath = filepath.Join(dir, "crl", base+".crl")
	}

	issuer, err := pki.LoadCert(caCert)
	if err != nil {
		return err
	}
	key, err := pki.LoadKey(caKey)
	if err != nil {
		return err
	}
	number, err := st.NextCRLNumber()
	if err != nil {
		return err
	}
	entries, err := st.Revoked()
	if err != nil {
		return err
	}
	now := time.Now()
	tmpl := &x509.RevocationList{
		Number:     number,
		ThisUpdate: now,
		NextUpdate: now.AddDate(0, 0, o.Days),
	}
	if tmpl.SignatureAlgorithm, err = pki.SignatureAlgorithm("sha512", key); err != nil {
		return err
	}
	for _, entry := range entries {
		tmpl.RevokedCertificateEntries = append(tmpl.RevokedCertificateEntries, x509.RevocationListEntry{
			SerialNumber:   entry.Serial,
			RevocationTime: entry.Time,
		})
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, issuer, key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(crlPath), 0755); err != nil {
		return err
	}
	if err := pki.WriteFile(crlPath, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}), 0644); err != nil {
		return err
	}
	log.Info("CRL written to %s\n", crlPath)
	return nil
}
