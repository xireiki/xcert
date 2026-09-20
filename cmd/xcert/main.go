package main

import (
	"os"

	"github.com/xireiki/xcert/log"
)

func main() {
	if err := newCLI().Execute(); err != nil {
		log.Error("%s", err)
		os.Exit(1)
	}
}
