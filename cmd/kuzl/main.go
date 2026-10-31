// Command kuzl is a read-only curl for AI agents: GET and HEAD only, nothing
// local is ever sent, and where requests may go is set by a policy built into
// the binary.
// Install it once and symlink it as curl: it picks the command tree by the
// name it is run as.
package main

import (
	"context"
	"os"

	"github.com/evadcmd/kuzl/internal/cli"
	"github.com/evadcmd/kuzl/internal/telemetry"
)

func main() {
	os.Exit(run())
}

// run is main without the os.Exit, so that the deferred flush runs first.
func run() int {
	log, shutdown := telemetry.Setup(context.Background())
	defer shutdown()
	return cli.Run(os.Args, cli.IO{In: os.Stdin, Out: os.Stdout, ErrOut: os.Stderr, Log: log})
}
