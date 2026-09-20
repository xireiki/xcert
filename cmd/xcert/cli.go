package main

import (
	"fmt"
	"os"
	"path/filepath"

	"xcert/log"
	"xcert/store"

	"github.com/spf13/cobra"
)

const (
	defaultRootSubject = "/C=CN/O=Test SSL/CN=Test SSL CA"
	defaultInteSubject = "/C=CN/O=Test SSL/CN=Test Inte CA"
	defaultCertSubject = "/C=CN"
)

var progName = filepath.Base(os.Args[0])

var legacyMode bool

func openStore(dir string) (*store.Store, error) {
	st, err := store.Open(filepath.Join(dir, store.FileName))
	if err != nil {
		return nil, err
	}
	if legacyMode {
		if err := st.LoadLegacy(dir); err != nil {
			st.Close()
			return nil, err
		}
	}
	return st, nil
}

func newCLI() *cobra.Command {
	var logLevel string
	root := &cobra.Command{
		Use:           progName,
		Short:         "X.509 certificate authority toolkit",
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.ArbitraryArgs,
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			level, err := log.ParseLevel(logLevel)
			if err != nil {
				return err
			}
			log.SetLevel(level)
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("Use \"%s help\" to view the help text", cmd.Name())
			}
			return fmt.Errorf("Unknown subcommand %s, use \"%s help\" for help", args[0], cmd.Name())
		},
	}
	root.PersistentFlags().StringVar(&logLevel, "log-level", "info", "log level (trace, debug, info, warn, error, fatal, panic)")
	root.PersistentFlags().BoolVar(&legacyMode, "legacy", false, "read the deprecated xcert.sh serial and index.txt files")
	root.AddCommand(newRootCommand(), newInteCommand(), newCertCommand(), newDBCommand())
	return root
}
