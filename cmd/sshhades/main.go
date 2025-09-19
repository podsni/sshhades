package main

import (
	"fmt"
	"os"

	"github.com/sshhades/sshhades/internal/cli"
)

var (
	version   = "dev"
	buildTime = "unknown"
	gitCommit = "unknown"
)

func main() {
	if err := cli.NewRootCommand(version, buildTime, gitCommit).Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}