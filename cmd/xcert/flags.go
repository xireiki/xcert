package main

import (
	"fmt"

	"github.com/xireiki/xcert/option"

	"github.com/spf13/cobra"
)

func addKeyFlags(cmd *cobra.Command, o *option.KeyOptions, defaults option.KeyOptions) {
	f := cmd.Flags()
	f.StringVarP(&o.Cipher, "cipher", "C", defaults.Cipher, "private key cipher (ecc, rsa, ed25519)")
	f.IntVar(&o.Bits, "rsa-bits", defaults.Bits, "key length for RSA private keys")
	f.StringVarP(&o.Subject, "subject", "s", defaults.Subject, "subject information")
	f.IntVar(&o.Days, "days", defaults.Days, "expiration time in days")
}

func addCAFlags(cmd *cobra.Command, o *option.CAOptions, defaults option.CAOptions) {
	f := cmd.Flags()
	f.StringSliceVar(&o.KeyUsage, "key-usage", defaults.KeyUsage, "key usage extension (comma separated)")
	f.StringSliceVar(&o.ExtKeyUsage, "ext-key-usage", defaults.ExtKeyUsage, "extended key usage extension (comma separated)")
	f.IntVar(&o.PathLength, "path-length", defaults.PathLength, "CA path length, -1 for unset")
	f.StringVar(&o.Digest, "digest", defaults.Digest, "signature digest algorithm (sha256, sha384, sha512)")
	f.BoolVar(&o.SubjectKeyID, "subject-key-id", defaults.SubjectKeyID, "include subject key identifier")
	f.BoolVar(&o.AuthorityKeyID, "authority-key-id", defaults.AuthorityKeyID, "include authority key identifier")
}

func containsString(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

func validateDays(name string, days int) error {
	if days <= 0 {
		return fmt.Errorf("%s must be positive", name)
	}
	return nil
}
