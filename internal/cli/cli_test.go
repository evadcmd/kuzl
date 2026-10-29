package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func run(args ...string) (code int, stdout, stderr string) {
	var out, errOut bytes.Buffer
	code = Run(args, IO{In: strings.NewReader(""), Out: &out, ErrOut: &errOut})
	return code, out.String(), errOut.String()
}

func TestRunDispatchesOnArgv0(t *testing.T) {
	tests := []struct {
		args []string
		want string
	}{
		{[]string{"/usr/local/bin/curl", "--version"}, "curl version dev\n"},
		{[]string{"/usr/local/bin/kuzl", "--version"}, "kuzl version dev\n"},
		{[]string{"kuzl", "curl", "--version"}, "curl version dev\n"},
		{[]string{"curl", "-V"}, "curl version dev\n"},
		// Any other name is kuzl.
		{[]string{"./kuzl-dev", "--version"}, "kuzl version dev\n"},
	}
	for _, tt := range tests {
		t.Run(strings.Join(tt.args, " "), func(t *testing.T) {
			code, stdout, stderr := run(tt.args...)
			if code != exitOK || stdout != tt.want || stderr != "" {
				t.Errorf("got (%d, %q, %q), want (%d, %q, \"\")", code, stdout, stderr, exitOK, tt.want)
			}
		})
	}
}

// A flag curl can't use exits 2, as curl does for an unknown option.
func TestRunReportsFlagErrorsWithoutUsage(t *testing.T) {
	tests := []struct {
		args []string
		want string
	}{
		{[]string{"curl", "--no-such-flag"}, "curl: unknown flag: --no-such-flag\nRun 'curl --help' for usage.\n"},
		{[]string{"kuzl", "curl", "--no-such-flag"}, "curl: unknown flag: --no-such-flag\nRun 'curl --help' for usage.\n"},
		{[]string{"kuzl", "--no-such-flag"}, "kuzl: unknown flag: --no-such-flag\nRun 'kuzl --help' for usage.\n"},
		// -v is curl's --verbose, so it must not print the version.
		{[]string{"curl", "-v"}, "curl: unknown shorthand flag: 'v' in -v\nRun 'curl --help' for usage.\n"},
	}
	for _, tt := range tests {
		t.Run(strings.Join(tt.args, " "), func(t *testing.T) {
			code, stdout, stderr := run(tt.args...)
			if code != exitUsage || stdout != "" || stderr != tt.want {
				t.Errorf("got (%d, %q, %q), want (%d, \"\", %q)", code, stdout, stderr, exitUsage, tt.want)
			}
		})
	}
}

// An unknown command is a command line kuzl can't use, as an unknown flag is.
func TestRunRejectsUnknownCommands(t *testing.T) {
	tests := []struct {
		args []string
		want string
	}{
		{[]string{"kuzl", "bogus"}, `kuzl: unknown command "bogus" for "kuzl"` + "\nRun 'kuzl --help' for usage.\n"},
		// An unknown command followed by a flag is still an unknown command,
		// not an unknown flag of its parent.
		{[]string{"kuzl", "wget", "-O", "x"}, `kuzl: unknown command "wget" for "kuzl"` + "\nRun 'kuzl --help' for usage.\n"},
	}
	for _, tt := range tests {
		t.Run(strings.Join(tt.args, " "), func(t *testing.T) {
			code, stdout, stderr := run(tt.args...)
			if code != exitUsage || stdout != "" || stderr != tt.want {
				t.Errorf("got (%d, %q, %q), want (%d, \"\", %q)", code, stdout, stderr, exitUsage, tt.want)
			}
		})
	}
}

// Under kuzl, curl prints its usage as the command the caller types.
func TestRunNamesSubtreeAsCurl(t *testing.T) {
	_, stdout, _ := run("kuzl", "curl", "--help")
	if !strings.Contains(stdout, "  curl ") || strings.Contains(stdout, "kuzl") {
		t.Errorf("help = %q, want usage curl", stdout)
	}
	_, stdout, _ = run("kuzl", "--help")
	if !strings.Contains(stdout, "  curl ") {
		t.Errorf("kuzl help = %q, want curl listed", stdout)
	}
}

func TestRunPrintsHelpWithoutArgs(t *testing.T) {
	for _, args := range [][]string{{"kuzl"}, {"curl"}, {"kuzl", "curl"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			code, stdout, stderr := run(args...)
			if code != exitOK || !strings.Contains(stdout, "Usage:") || stderr != "" {
				t.Errorf("got (%d, %q, %q), want help on stdout and exit %d", code, stdout, stderr, exitOK)
			}
		})
	}
}

func TestRunLogsOneRecordOffTheOutput(t *testing.T) {
	var out, errOut, logged bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logged, nil))
	code := Run([]string{"kuzl", "bogus"}, IO{In: strings.NewReader(""), Out: &out, ErrOut: &errOut, Log: log})

	var rec map[string]any
	if err := json.Unmarshal(logged.Bytes(), &rec); err != nil {
		t.Fatalf("log = %q, want one JSON record: %v", logged.String(), err)
	}
	if rec["level"] != "ERROR" || rec["name"] != "kuzl" || rec["command"] != "kuzl" ||
		rec["exit_code"] != float64(code) || rec["error_kind"] != "usage" {
		t.Errorf("record = %v", rec)
	}
	if _, ok := rec["duration_ms"].(float64); !ok {
		t.Errorf("duration_ms = %v, want a number", rec["duration_ms"])
	}
	if strings.Contains(out.String()+errOut.String(), `"exit_code"`) {
		t.Errorf("the record leaked into the output: stdout %q, stderr %q", out.String(), errOut.String())
	}
}

// The record names the command and the flags that were set, not the raw args,
// which can hold tokens in a URL or a header.
func TestRunLogsFlagNamesNotArgs(t *testing.T) {
	var logged bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logged, nil))
	s := IO{In: strings.NewReader(""), Out: &bytes.Buffer{}, ErrOut: &bytes.Buffer{}, Log: log}
	Run([]string{"kuzl", "curl", "--version=true"}, s)

	var rec map[string]any
	if err := json.Unmarshal(logged.Bytes(), &rec); err != nil {
		t.Fatalf("log = %q, want one JSON record: %v", logged.String(), err)
	}
	if rec["name"] != "kuzl" || rec["command"] != "curl" || fmt.Sprint(rec["flags"]) != "[version]" {
		t.Errorf("record = %v, want name kuzl, command curl and flags [version]", rec)
	}
	if _, ok := rec["args"]; ok || strings.Contains(logged.String(), "--version=true") {
		t.Errorf("log = %q, want no raw args", logged.String())
	}
}

// cobra and pflag quote the offending arg in their errors, which stderr shows
// but the record must not.
func TestRunLogsNoArgsOnError(t *testing.T) {
	const secret = "SEKRET"
	for _, args := range [][]string{
		{"curl", "https://h/?token=" + secret},
		{"curl", "-x" + secret},
		{"curl", "--version=" + secret},
		{"kuzl", secret},
		{"kuzl", secret, "-O", "x"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var errOut, logged bytes.Buffer
			log := slog.New(slog.NewJSONHandler(&logged, nil))
			Run(args, IO{In: strings.NewReader(""), Out: &bytes.Buffer{}, ErrOut: &errOut, Log: log})
			if !strings.Contains(errOut.String(), secret) {
				t.Fatalf("stderr = %q, want the error to quote the arg", errOut.String())
			}
			if strings.Contains(logged.String(), secret) {
				t.Errorf("log = %q, want no args", logged.String())
			}
		})
	}
}

func TestRunHasNoCompletionCommand(t *testing.T) {
	code, _, stderr := run("kuzl", "completion", "bash")
	if code != exitUsage || !strings.Contains(stderr, `unknown command "completion"`) {
		t.Errorf("got (%d, %q), want an unknown command error", code, stderr)
	}
}
