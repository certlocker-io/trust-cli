package main

import (
	"os"

	"github.com/certlocker-io/trust-cli/internal/cli"
)

func main() {
	if err := cli.New().Execute(); err != nil {
		os.Exit(1)
	}
}
