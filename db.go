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

	"github.com/spf13/cobra"
)

func newDBCmd() *cobra.Command {
	var dir string
	cmd := &cobra.Command{
		Use:           "db",
		Short:         "Manage the certificate database",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.SetHelpFunc(usageHelp)
	cmd.PersistentFlags().StringVarP(&dir, "dir", "D", ".", "certificate directory")
	cmd.AddCommand(
		dbListCmd(&dir),
		dbShowCmd(&dir),
		dbDeleteCmd(&dir),
		dbRevokeCmd(&dir),
		dbUnrevokeCmd(&dir),
	)
	return cmd
}

func usageHelp(cmd *cobra.Command, _ []string) {
	out := cmd.OutOrStdout()
	if cmd.Long != "" {
		fmt.Fprintln(out, cmd.Long)
	} else if cmd.Short != "" {
		fmt.Fprintln(out, cmd.Short)
	}
	fmt.Fprintln(out)
	fmt.Fprint(out, cmd.UsageString())
}

func dbListCmd(dir *string) *cobra.Command {
	return &cobra.Command{
		Use:           "list",
		Short:         "List all records",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := openStore(filepath.Join(*dir, dbFileName))
			if err != nil {
				return err
			}
			defer st.close()
			recs, err := st.list()
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "SERIAL\tTYPE\tNAME\tSTATUS\tNOT_AFTER")
			for _, r := range recs {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", r.Serial, r.Type, r.Name, r.Status, r.NotAfter)
			}
			return w.Flush()
		},
	}
}

func dbShowCmd(dir *string) *cobra.Command {
	return &cobra.Command{
		Use:           "show <serial|name>",
		Short:         "Show a record",
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := openStore(filepath.Join(*dir, dbFileName))
			if err != nil {
				return err
			}
			defer st.close()
			r, err := st.resolve(args[0])
			if err != nil {
				return err
			}
			revoked := ""
			if r.RevokedAt.Valid {
				revoked = r.RevokedAt.String
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
`, r.Serial, r.Type, r.Name, r.Subject, r.Status, r.NotBefore, r.NotAfter, r.CertPath, r.KeyPath, r.CreatedAt, revoked)
			return nil
		},
	}
}

func dbDeleteCmd(dir *string) *cobra.Command {
	return &cobra.Command{
		Use:           "delete <serial|name>",
		Short:         "Delete a record",
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := openStore(filepath.Join(*dir, dbFileName))
			if err != nil {
				return err
			}
			defer st.close()
			r, err := st.delete(args[0])
			if err != nil {
				return err
			}
			info("Deleted %s (%s)\n", r.Serial, r.Name)
			return nil
		},
	}
}

type crlOptions struct {
	caCert  string
	caKey   string
	crl     string
	crlDays int
}

func addCRLFlags(cmd *cobra.Command, o *crlOptions) {
	f := cmd.Flags()
	f.StringVar(&o.caCert, "ca-cert", "", "CA certificate used to sign the CRL")
	f.StringVar(&o.caKey, "ca-key", "", "CA private key used to sign the CRL")
	f.StringVar(&o.crl, "crl", "", "output CRL file")
	f.IntVar(&o.crlDays, "crl-days", 30, "CRL validity in days")
}

func dbRevokeCmd(dir *string) *cobra.Command {
	o := &crlOptions{}
	cmd := &cobra.Command{
		Use:           "revoke <serial|name>",
		Short:         "Revoke a certificate and update the CRL",
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSetStatus(*dir, args[0], "R", o)
		},
	}
	addCRLFlags(cmd, o)
	return cmd
}

func dbUnrevokeCmd(dir *string) *cobra.Command {
	o := &crlOptions{}
	cmd := &cobra.Command{
		Use:           "unrevoke <serial|name>",
		Short:         "Unrevoke a certificate and update the CRL",
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSetStatus(*dir, args[0], "V", o)
		},
	}
	addCRLFlags(cmd, o)
	return cmd
}

func runSetStatus(dir, selector, status string, o *crlOptions) error {
	st, err := openStore(filepath.Join(dir, dbFileName))
	if err != nil {
		return err
	}
	defer st.close()

	rec, err := st.setStatus(selector, status)
	if err != nil {
		return err
	}
	verb := "Revoked"
	if status == "V" {
		verb = "Unrevoked"
	}
	info("%s %s (%s)\n", verb, rec.Serial, rec.Name)

	if err := writeCRL(dir, o, st); err != nil {
		return err
	}
	return nil
}

func writeCRL(dir string, o *crlOptions, st *store) error {
	caCert := o.caCert
	if caCert == "" {
		caCert = filepath.Join(dir, "InteCA.cer")
	}
	caKey := o.caKey
	if caKey == "" {
		caKey = filepath.Join(dir, "InteCA.key")
	}
	crlPath := o.crl
	if crlPath == "" {
		base := strings.TrimSuffix(filepath.Base(caCert), filepath.Ext(caCert))
		crlPath = filepath.Join(dir, "crl", base+".crl")
	}

	issuer, err := loadCert(caCert)
	if err != nil {
		return err
	}
	key, err := loadKey(caKey)
	if err != nil {
		return err
	}
	number, err := st.nextCRLNumber()
	if err != nil {
		return err
	}
	entries, err := st.revoked()
	if err != nil {
		return err
	}
	now := time.Now()
	tmpl := &x509.RevocationList{
		Number:             number,
		ThisUpdate:         now,
		NextUpdate:         now.AddDate(0, 0, o.crlDays),
		SignatureAlgorithm: sigAlg(key),
	}
	for _, e := range entries {
		tmpl.RevokedCertificateEntries = append(tmpl.RevokedCertificateEntries, x509.RevocationListEntry{
			SerialNumber:   e.Serial,
			RevocationTime: e.Time,
		})
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, issuer, key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(crlPath), 0755); err != nil {
		return err
	}
	if err := writeFile(crlPath, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}), 0644); err != nil {
		return err
	}
	info("CRL written to %s\n", crlPath)
	return nil
}
