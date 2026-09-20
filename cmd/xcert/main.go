package main

import (
	"os"

	"xcert/log"
)

func main() {
	if err := newCLI().Execute(); err != nil {
		log.Error("%s\n", err)
		os.Exit(1)
	}
}
