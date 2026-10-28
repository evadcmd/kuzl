// Package cli builds the command trees. One binary serves as curl and kuzl,
// picked by the name it is invoked as (argv[0]), the way busybox does; under
// any other name it is kuzl, which has curl as a subcommand.
package cli

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// version is set at build time with -ldflags "-X ...cli.version=...".
var version = "dev"

const (
	exitOK    = 0
	exitError = 1
	// exitUsage is curl's exit code for a command line it can't use
	// (CURLE_FAILED_INIT), such as an unknown option.
	exitUsage = 2
)

// IO is where commands read input and write output, so tests can capture it.
type IO struct {
	In     io.Reader
	Out    io.Writer
	ErrOut io.Writer
	// Log gets one record per run, for kuzl's own telemetry; nil drops it.
	// It must not write to Out or ErrOut, which only carry what curl would
	// print.
	Log *slog.Logger
}

// Run executes the command line args (args[0] included) and returns the exit
// code. Errors go to ErrOut, prefixed with the name the binary was run as.
//
// The log record names the command and the flags that were set, but carries
// no positional args or flag values: those can be URLs with tokens in their
// query, or headers.
func Run(args []string, s IO) int {
	log := s.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	invokedAs := filepath.Base(args[0])
	name := invokedAs
	// kuzl curl runs as curl does, so that usage lines, help and errors name
	// the command the caller would type.
	if name != "curl" && len(args) > 1 && args[1] == "curl" {
		name, args = args[1], args[1:]
	}
	cmd := newCommand(name, s)
	cmd.SetArgs(args[1:])
	start := time.Now()
	ran, err := cmd.ExecuteC()
	attrs := []any{
		"name", invokedAs,
		"command", ran.CommandPath(),
		"flags", setFlags(ran),
		"duration_ms", time.Since(start).Milliseconds(),
	}
	if err != nil {
		code := exitError
		_, _ = fmt.Fprintf(s.ErrOut, "%s: %v\n", name, err)
		if fe, ok := errors.AsType[*flagError](err); ok {
			code = exitUsage
			_, _ = fmt.Fprintf(s.ErrOut, "Run '%s --help' for usage.\n", fe.cmdPath)
		}
		log.Error("run", append(attrs, "exit_code", code, "error", err)...)
		return code
	}
	log.Info("run", append(attrs, "exit_code", exitOK)...)
	return exitOK
}

// setFlags returns the names of the flags set on the command line, sorted.
func setFlags(cmd *cobra.Command) []string {
	names := []string{}
	cmd.Flags().Visit(func(f *pflag.Flag) { names = append(names, f.Name) })
	return names
}

func newCommand(name string, s IO) *cobra.Command {
	switch name {
	case "curl":
		return newCurlCmd(s)
	default:
		cmd := newRoot("kuzl", "A read-only curl for agents", s)
		cmd.AddCommand(newCurlCmd(s))
		return cmd
	}
}

func newCurlCmd(s IO) *cobra.Command {
	cmd := newRoot("curl", "Fetch a URL with GET or HEAD", s)
	// curl's version flag is -V; cobra's default would take -v, which is
	// curl's --verbose. cobra uses a version flag that is already defined.
	cmd.Flags().BoolP("version", "V", false, "version for curl")
	return cmd
}

// newRoot returns a top-level command with the settings every tree shares.
// Usage isn't printed on errors: the caller is an agent, and a full help page
// per mistake costs more context than the one-line hint does.
//
// The command is runnable, printing its help, so that cobra checks its args:
// a command without Run returns help with a nil error before validating
// them, and an unknown subcommand would then exit 0.
func newRoot(use, short string, s IO) *cobra.Command {
	cmd := &cobra.Command{
		Use:           use,
		Short:         short,
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE:          func(c *cobra.Command, _ []string) error { return c.Help() },
	}
	cmd.CompletionOptions.DisableDefaultCmd = true
	cmd.SetIn(s.In)
	cmd.SetOut(s.Out)
	cmd.SetErr(s.ErrOut)
	cmd.SetFlagErrorFunc(func(c *cobra.Command, err error) error {
		// cobra parses flags on the last command it found, so an unknown
		// subcommand followed by a flag, as in kuzl wget -O x, fails on the
		// flag; the subcommand is what is wrong. pflag has kept the
		// positional args before the bad flag, the subcommand first.
		if c.HasSubCommands() && c.Flags().NArg() > 0 {
			err = fmt.Errorf("unknown command %q for %q", c.Flags().Arg(0), c.CommandPath())
		}
		return &flagError{err: err, cmdPath: c.CommandPath()}
	})
	return cmd
}

// flagError is a flag parsing error, which Run follows with a pointer to the
// command's help.
type flagError struct {
	err     error
	cmdPath string
}

func (e *flagError) Error() string { return e.err.Error() }
func (e *flagError) Unwrap() error { return e.err }
