package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/xireiki/xcert/pki"

	"github.com/spf13/cobra"
)

func newInfoCommand() *cobra.Command {
	var file string
	cmd := &cobra.Command{
		Use:           "info",
		Short:         "Show detailed information about a certificate file",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if file == "" {
				return fmt.Errorf("certificate file is required, use -f/--file")
			}
			cert, err := pki.LoadCert(file)
			if err != nil {
				return err
			}
			printCertInfo(cmd.OutOrStdout(), file, cert)
			return nil
		},
	}
	cmd.Flags().StringVarP(&file, "file", "f", "", "certificate file")
	return cmd
}

func printCertInfo(w io.Writer, path string, cert *x509.Certificate) {
	fmt.Fprintf(w, "File:          %s\n", path)
	fmt.Fprintf(w, "Subject:       %s\n", cert.Subject)
	fmt.Fprintf(w, "Issuer:        %s\n", cert.Issuer)
	fmt.Fprintf(w, "Serial:        %X\n", cert.SerialNumber)
	fmt.Fprintf(w, "Version:       %d\n", cert.Version)
	fmt.Fprintf(w, "NotBefore:     %s\n", cert.NotBefore.UTC().Format(time.RFC3339))
	fmt.Fprintf(w, "NotAfter:      %s\n", cert.NotAfter.UTC().Format(time.RFC3339))
	fmt.Fprintf(w, "IsCA:          %t\n", cert.IsCA)
	if cert.IsCA {
		pathLength := "unset"
		if cert.MaxPathLen > 0 || cert.MaxPathLenZero {
			pathLength = fmt.Sprintf("%d", cert.MaxPathLen)
		}
		fmt.Fprintf(w, "PathLength:    %s\n", pathLength)
	}
	fmt.Fprintf(w, "KeyUsage:      %s\n", formatKeyUsage(cert.KeyUsage))
	fmt.Fprintf(w, "ExtKeyUsage:   %s\n", formatExtKeyUsage(cert.ExtKeyUsage))
	fmt.Fprintf(w, "DNSNames:      %s\n", strings.Join(cert.DNSNames, ", "))
	fmt.Fprintf(w, "PublicKey:     %s\n", formatPublicKey(cert.PublicKey))
	fmt.Fprintf(w, "Signature:     %s\n", cert.SignatureAlgorithm)
	if len(cert.SubjectKeyId) > 0 {
		fmt.Fprintf(w, "SubjectKeyId:  %X\n", cert.SubjectKeyId)
	}
	if len(cert.AuthorityKeyId) > 0 {
		fmt.Fprintf(w, "AuthorityKeyId: %X\n", cert.AuthorityKeyId)
	}
	fingerprint := sha256.Sum256(cert.Raw)
	fmt.Fprintf(w, "SHA256:        %s\n", formatFingerprint(fingerprint[:]))
}

var keyUsageLabels = []struct {
	usage x509.KeyUsage
	name  string
}{
	{x509.KeyUsageDigitalSignature, "digitalSignature"},
	{x509.KeyUsageContentCommitment, "nonRepudiation"},
	{x509.KeyUsageKeyEncipherment, "keyEncipherment"},
	{x509.KeyUsageDataEncipherment, "dataEncipherment"},
	{x509.KeyUsageKeyAgreement, "keyAgreement"},
	{x509.KeyUsageCertSign, "keyCertSign"},
	{x509.KeyUsageCRLSign, "cRLSign"},
	{x509.KeyUsageEncipherOnly, "encipherOnly"},
	{x509.KeyUsageDecipherOnly, "decipherOnly"},
}

func formatKeyUsage(usage x509.KeyUsage) string {
	var names []string
	for _, item := range keyUsageLabels {
		if usage&item.usage != 0 {
			names = append(names, item.name)
		}
	}
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ", ")
}

var extKeyUsageLabels = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageServerAuth:      "serverAuth",
	x509.ExtKeyUsageClientAuth:      "clientAuth",
	x509.ExtKeyUsageCodeSigning:     "codeSigning",
	x509.ExtKeyUsageEmailProtection: "emailProtection",
	x509.ExtKeyUsageIPSECEndSystem:  "ipsecEndSystem",
	x509.ExtKeyUsageIPSECTunnel:     "ipsecTunnel",
	x509.ExtKeyUsageIPSECUser:       "ipsecUser",
	x509.ExtKeyUsageTimeStamping:    "timeStamping",
	x509.ExtKeyUsageOCSPSigning:     "ocspSigning",
	x509.ExtKeyUsageAny:             "any",
}

func formatExtKeyUsage(usages []x509.ExtKeyUsage) string {
	if len(usages) == 0 {
		return "none"
	}
	var names []string
	for _, usage := range usages {
		if name, ok := extKeyUsageLabels[usage]; ok {
			names = append(names, name)
		} else {
			names = append(names, fmt.Sprintf("%d", usage))
		}
	}
	return strings.Join(names, ", ")
}

func formatPublicKey(key any) string {
	switch k := key.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d bits", k.N.BitLen())
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ECDSA %s %d bits", k.Curve.Params().Name, k.Curve.Params().BitSize)
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return fmt.Sprintf("%T", key)
	}
}

func formatFingerprint(data []byte) string {
	parts := make([]string, len(data))
	for i, b := range data {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}
