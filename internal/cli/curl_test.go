package cli

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/evadcmd/kuzl/internal/config"
	"github.com/evadcmd/kuzl/internal/netguard"
	"github.com/evadcmd/kuzl/internal/workspace"
)

// fakeNet stands in for DNS and the network, as netguard's tests do: names
// resolve from hosts, and every dial reaches the one loopback test server,
// which tells the virtual hosts apart by the Host header.
type fakeNet struct {
	server   string
	root     string // KUZL_ROOT
	requests atomic.Int32
}

var fakeHosts = map[string]string{
	"public.test":     "8.8.8.8",
	"sub.public.test": "8.8.4.4",
	"denied.test":     "8.8.8.8",
	"loopback.test":   "127.0.0.1",
	"down.test":       "1.1.1.1",
}

func (f *fakeNet) LookupNetIP(ctx context.Context, _, host string) ([]netip.Addr, error) {
	// slowdns.test never answers, as a hung resolver doesn't.
	if host == "slowdns.test" {
		select {
		case <-ctx.Done():
			return nil, &net.DNSError{Err: "i/o timeout", Name: host, IsTimeout: true}
		case <-time.After(5 * time.Second):
			return nil, errors.New("slowdns.test: no deadline")
		}
	}
	ip, ok := fakeHosts[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return []netip.Addr{netip.MustParseAddr(ip)}, nil
}

func (f *fakeNet) dial(ctx context.Context, network, address string) (net.Conn, error) {
	if strings.HasPrefix(address, "1.1.1.1:") {
		return nil, &net.OpError{Op: "dial", Net: network, Err: errors.New("connection refused")}
	}
	var d net.Dialer
	return d.DialContext(ctx, network, f.server)
}

// newFakeNet starts a server for the virtual hosts:
//   - /to?u=URL redirects to URL;
//   - /headers echoes some request headers and the method;
//   - /status?code=N answers N with a body;
//   - /big?n=N sends N bytes of b, with ?s=S of them first and chunked=1
//     without a Content-Length;
//   - /binary, /latin1 and /gzip send what they say, /binary with status
//     ?code=N if given;
//   - /slow waits for the client to give up;
//   - /query echoes the method and the raw query;
//   - anything else says hello.
func newFakeNet(t *testing.T) *fakeNet {
	t.Helper()
	f := &fakeNet{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		q := r.URL.Query()
		switch r.URL.Path {
		case "/to":
			http.Redirect(w, r, q.Get("u"), http.StatusFound) //nolint:gosec // G710: the open redirect is what the test needs.
		case "/headers":
			for _, h := range []string{"Accept", "User-Agent", "Referer", "Authorization", "Range", "X-A", "X-Empty"} {
				if v, ok := r.Header[h]; ok {
					_, _ = fmt.Fprintf(w, "%s=%q\n", h, v) //nolint:gosec // G705: a plain-text echo for the test.
				}
			}
			_, _ = fmt.Fprintf(w, "method=%s\n", r.Method) //nolint:gosec // G705: a plain-text echo for the test.
		case "/status":
			code, _ := strconv.Atoi(q.Get("code"))
			w.WriteHeader(code)
			_, _ = io.WriteString(w, "status body")
		case "/big":
			n, _ := strconv.Atoi(q.Get("n"))
			s := q.Get("s")
			if q.Get("chunked") == "" {
				w.Header().Set("Content-Length", strconv.Itoa(len(s)+n))
			}
			_, _ = io.WriteString(w, s) //nolint:gosec // G705: a plain-text echo for the test.
			w.(http.Flusher).Flush()
			_, _ = w.Write(bytes.Repeat([]byte("b"), n))
		case "/binary":
			w.Header().Set("Content-Type", "image/png")
			if code, _ := strconv.Atoi(q.Get("code")); code != 0 {
				w.WriteHeader(code)
			}
			_, _ = w.Write([]byte("\x89PNG\r\n\x1a\n\x00\x00"))
		case "/latin1":
			_, _ = w.Write([]byte("caf\xe9"))
		case "/gzip":
			w.Header().Set("Content-Encoding", "gzip")
			gz := gzip.NewWriter(w)
			_, _ = io.WriteString(gz, "unzipped")
			_ = gz.Close()
		case "/slow":
			select {
			case <-r.Context().Done():
			case <-time.After(10 * time.Second):
			}
		case "/query":
			_, _ = fmt.Fprintf(w, "%s %s", r.Method, r.URL.RawQuery) //nolint:gosec // G705: a plain-text echo for the test.
		default:
			_, _ = io.WriteString(w, "hello from "+r.Host) //nolint:gosec // G705: a plain-text echo for the test.
		}
	}))
	t.Cleanup(srv.Close)
	f.server = srv.Listener.Addr().String()
	f.root = t.TempDir()
	return f
}

func (f *fakeNet) io(t *testing.T, out, errOut io.Writer, log *slog.Logger) IO {
	t.Helper()
	allow, _ := netguard.ParseHostPattern("*")
	deny, _ := netguard.ParseHostPattern("denied.test")
	p := netguard.NewPolicy(netguard.Rules{AllowHosts: []netguard.HostPattern{allow}, DenyHosts: []netguard.HostPattern{deny}})
	return IO{
		In: strings.NewReader(""), Out: out, ErrOut: errOut, Log: log,
		Client: func(o netguard.Options) (*http.Client, error) { return p.ClientOver(o, f, f.dial), nil },
		Getenv: func(k string) string {
			if k == workspace.EnvRoot {
				return f.root
			}
			return ""
		},
	}
}

func (f *fakeNet) curl(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = Run(append([]string{"curl"}, args...), f.io(t, &out, &errOut, nil))
	return code, out.String(), errOut.String()
}

type want struct {
	code           int
	stdout, stderr string
}

func check(t *testing.T, f *fakeNet, args []string, w want) {
	t.Helper()
	code, stdout, stderr := f.curl(t, args...)
	if code != w.code || stdout != w.stdout || stderr != w.stderr {
		t.Errorf("curl %s:\ngot  (%d, %q, %q)\nwant (%d, %q, %q)", clip(strings.Join(args, " ")), code, clip(stdout), stderr, w.code, clip(w.stdout), w.stderr)
	}
}

// clip shortens s for a failure message, keeping its length.
func clip(s string) string {
	if len(s) <= 200 {
		return s
	}
	return fmt.Sprintf("%s…(%d bytes)…%s", s[:100], len(s), s[len(s)-100:])
}

func TestCurlGet(t *testing.T) {
	f := newFakeNet(t)
	check(t, f, []string{"http://public.test/"}, want{exitOK, "hello from public.test", ""})
	// As curl does, a URL without a scheme is http, and the fragment isn't
	// sent.
	check(t, f, []string{"public.test/#frag"}, want{exitOK, "hello from public.test", ""})
	// Only a scheme at the start counts, not "://" in the query.
	check(t, f, []string{"public.test/?next=https://x.test/"}, want{exitOK, "hello from public.test", ""})
	check(t, f, []string{"public.test:80/x"}, want{exitOK, "hello from public.test:80", ""})
	// Go's client asks for gzip and decompresses it.
	check(t, f, []string{"--compressed", "http://public.test/gzip"}, want{exitOK, "unzipped", ""})
}

func TestCurlRequestHeaders(t *testing.T) {
	f := newFakeNet(t)
	const url = "http://public.test/headers"
	tests := []struct {
		args []string
		want string
	}{
		{nil, "Accept=[\"*/*\"]\nUser-Agent=[\"kuzl/dev\"]\nmethod=GET\n"},
		{[]string{"-A", "bot/1", "-e", "http://ref.test/"}, "Accept=[\"*/*\"]\nUser-Agent=[\"bot/1\"]\nReferer=[\"http://ref.test/\"]\nmethod=GET\n"},
		// An empty -A sends no User-Agent, as "User-Agent:" does.
		{[]string{"-A", ""}, "Accept=[\"*/*\"]\nmethod=GET\n"},
		{[]string{"-H", "User-Agent:"}, "Accept=[\"*/*\"]\nmethod=GET\n"},
		// -H replaces a header kuzl sets, adds to one it set itself, removes
		// with "Name:" and sends an empty one with "Name;".
		{
			[]string{"-A", "bot/1", "-H", "accept: application/json", "-H", "X-A: 1", "-H", "X-A:  2 ", "-H", "Authorization: Bearer t", "-H", "X-Empty;"},
			"Accept=[\"application/json\"]\nUser-Agent=[\"bot/1\"]\nAuthorization=[\"Bearer t\"]\nX-A=[\"1\" \"2\"]\nX-Empty=[\"\"]\nmethod=GET\n",
		},
		{[]string{"-H", "Accept:", "-X", "GET"}, "User-Agent=[\"kuzl/dev\"]\nmethod=GET\n"},
	}
	for _, tt := range tests {
		check(t, f, append(tt.args, url), want{exitOK, tt.want, ""})
	}
}

func TestCurlRejectsBadHeaders(t *testing.T) {
	f := newFakeNet(t)
	const url = "http://public.test/"
	hint := "Run 'curl --help' for usage.\n"
	tests := []struct {
		header string
		want   want
	}{
		{"@/etc/passwd", want{exitUsage, "", "curl: -H @file is not supported: kuzl reads no local files\n"}},
		{"Host: denied.test", want{exitUsage, "", "curl: -H Host is not supported: the request goes to the URL's host\n"}},
		{"host;", want{exitUsage, "", "curl: -H Host is not supported: the request goes to the URL's host\n"}},
		{"NoColon", want{exitUsage, "", "curl: -H \"NoColon\" is not a header: want \"Name: value\"\n" + hint}},
		{"Bad Name: x", want{exitUsage, "", "curl: -H \"Bad Name: x\": \"Bad Name\" is not a header name\n" + hint}},
		{"X-A: a\x00b", want{exitUsage, "", "curl: -H \"X-A: a\\x00b\": a header value can't hold control characters\n" + hint}},
	}
	for _, tt := range tests {
		check(t, f, []string{"-H", tt.header, url}, tt.want)
	}
	if n := f.requests.Load(); n != 0 {
		t.Errorf("%d requests sent, want none", n)
	}
}

// Flags that would send data, read or write a file, or go around the policy
// are refused with a reason, before anything is sent, even with -s.
func TestCurlRefusesFlags(t *testing.T) {
	f := newFakeNet(t)
	const url = "http://public.test/"
	tests := []struct {
		args []string
		want string
	}{
		{[]string{"-d", "@/home/app/.aws/credentials"}, "-d/--data without -G is not supported: kuzl only sends GET and HEAD; -G puts the data in the query string"},
		{[]string{"-s", "--data-binary=x"}, "--data-binary without -G is not supported: kuzl only sends GET and HEAD; -G puts the data in the query string"},
		{[]string{"-dx"}, "-d/--data without -G is not supported: kuzl only sends GET and HEAD; -G puts the data in the query string"},
		{[]string{"--data-urlencode", "q=x"}, "--data-urlencode without -G is not supported: kuzl only sends GET and HEAD; -G puts the data in the query string"},
		{[]string{"--json", "{}"}, "--json is not supported: kuzl only sends GET and HEAD"},
		{[]string{"-F", "f=@x"}, "-F/--form is not supported: kuzl only sends GET and HEAD"},
		// -G takes only the data flags: --json and -F stay refused.
		{[]string{"-G", "--json", "{}"}, "--json is not supported: kuzl only sends GET and HEAD"},
		{[]string{"-G", "-F", "f=x"}, "-F/--form is not supported: kuzl only sends GET and HEAD"},
		{[]string{"-T", "x"}, "-T/--upload-file is not supported: kuzl only sends GET and HEAD"},
		{[]string{"-K", "x"}, "-K/--config is not supported: kuzl reads no config file"},
		{[]string{"-u", "a:b"}, `-u/--user is not supported: set the header instead, as in -H "Authorization: Basic ..."`},
		{[]string{"-b", "jar.txt"}, `-b/--cookie is not supported: kuzl reads no cookie file; set the header instead, as in -H "Cookie: name=value"`},
		{[]string{"-c", "jar.txt"}, "-c/--cookie-jar is not supported: kuzl writes no cookie file"},
		{[]string{"-n"}, "-n/--netrc is not supported: kuzl reads no netrc file"},
		{[]string{"-x", "http://127.0.0.1:3128"}, "-x/--proxy is not supported: kuzl connects directly: through a proxy, its address check would only see the proxy's"},
		{[]string{"-k"}, "-k/--insecure is not supported: kuzl always verifies certificates"},
		{[]string{"--unix-socket", "/var/run/docker.sock"}, "--unix-socket is not supported: kuzl only connects to public addresses"},
		{[]string{"--resolve", "public.test:80:127.0.0.1"}, "--resolve is not supported: kuzl resolves names itself, so that the address it checks is the one it connects to"},
		{[]string{"--connect-to", "::127.0.0.1:"}, "--connect-to is not supported: kuzl resolves names itself, so that the address it checks is the one it connects to"},
		{[]string{"--location-trusted"}, "--location-trusted is not supported: kuzl never sends credentials to another origin on a redirect"},
		{[]string{"-X", "POST"}, "-X POST is not supported: kuzl only sends GET and HEAD"},
		{[]string{"-sXDELETE"}, "-X DELETE is not supported: kuzl only sends GET and HEAD"},
	}
	for _, tt := range tests {
		check(t, f, append(tt.args, url), want{exitUsage, "", "curl: " + tt.want + "\n"})
	}
	// Without a URL too: the reason beats the help page.
	check(t, f, []string{"-d", "x"}, want{exitUsage, "", "curl: -d/--data without -G is not supported: kuzl only sends GET and HEAD; -G puts the data in the query string\n"})
	check(t, f, []string{"-X", "PUT"}, want{exitUsage, "", "curl: -X PUT is not supported: kuzl only sends GET and HEAD\n"})
	if n := f.requests.Load(); n != 0 {
		t.Errorf("%d requests sent, want none", n)
	}
	// The refused flags stay out of the help.
	_, stdout, _ := f.curl(t, "--help")
	if strings.Contains(stdout, "--json") || strings.Contains(stdout, "--proxy") {
		t.Errorf("help lists refused flags:\n%s", stdout)
	}
}

func TestCurlRejectsBadCommandLines(t *testing.T) {
	f := newFakeNet(t)
	hint := "Run 'curl --help' for usage.\n"
	tests := []struct {
		args []string
		want string
	}{
		{[]string{"http://public.test/", "http://public.test/"}, "expected one URL, got 2"},
		{[]string{"-I", "-X", "GET", "http://public.test/"}, "-I sends HEAD, not -X GET"},
		{[]string{"-f", "--fail-with-body", "http://public.test/"}, "use -f or --fail-with-body, not both"},
		{[]string{"--max-redirs", "-2", "http://public.test/"}, "--max-redirs -2: want -1 (no limit) or more"},
		{[]string{"-m", "-1", "http://public.test/"}, "a timeout can't be negative"},
	}
	for _, tt := range tests {
		check(t, f, tt.args, want{exitUsage, "", "curl: " + tt.want + "\n" + hint})
	}
	check(t, f, []string{"http://[::1"}, want{exitURLMalformat, "", "curl: (3) URL rejected: missing ']' in host\n"})
}

func TestCurlHeadersOut(t *testing.T) {
	f := newFakeNet(t)
	_, stdout, _ := f.curl(t, "-I", "http://public.test/headers")
	if !strings.HasPrefix(stdout, "HTTP/1.1 200 OK\r\n") || !strings.HasSuffix(stdout, "\r\n\r\n") ||
		!strings.Contains(stdout, "\r\nContent-Type: text/plain; charset=utf-8\r\n") {
		t.Errorf("-I wrote %q, want the status line and headers", stdout)
	}
	// HEAD: the server saw it, and there is no body.
	check(t, f, []string{"-X", "HEAD", "http://public.test/headers"}, want{exitOK, "", ""})

	_, stdout, _ = f.curl(t, "-i", "http://public.test/headers")
	head, body, ok := strings.Cut(stdout, "\r\n\r\n")
	if !ok || !strings.HasPrefix(head, "HTTP/1.1 200 OK\r\n") || !strings.HasSuffix(body, "method=GET\n") {
		t.Errorf("-i wrote %q, want headers, a blank line and the body", stdout)
	}

	// -L writes every hop's headers, as curl does.
	_, stdout, _ = f.curl(t, "-sIL", "http://public.test/to?u=http://sub.public.test/")
	if !strings.HasPrefix(stdout, "HTTP/1.1 302 Found\r\n") || !strings.Contains(stdout, "\r\nLocation: http://sub.public.test/\r\n") ||
		!strings.Contains(stdout, "\r\n\r\nHTTP/1.1 200 OK\r\n") {
		t.Errorf("-IL wrote %q, want both hops", stdout)
	}
}

func TestCurlRedirects(t *testing.T) {
	f := newFakeNet(t)
	const to = "http://public.test/to?u="
	// Not following, the redirect is the response.
	_, stdout, _ := f.curl(t, to+"/")
	if !strings.Contains(stdout, "Found") {
		t.Errorf("without -L: %q, want the redirect's body", stdout)
	}
	check(t, f, []string{"-L", to + "http://sub.public.test/"}, want{exitOK, "hello from sub.public.test", ""})
	check(t, f, []string{"-L", "--max-redirs", "1", to + "/to%3Fu=/"}, want{exitTooManyRedirects, "", "curl: (47) Maximum (1) redirects followed\n"})
	// Every hop goes through the policy.
	check(t, f, []string{"-sL", to + "http://denied.test/"}, want{exitUsage, "", "curl: host denied.test is in deny_hosts\n"})
	check(t, f, []string{"-sL", to + "http://loopback.test/"}, want{exitUsage, "", "curl: host loopback.test has no address kuzl may dial: 127.0.0.1 is not public\n"})
}

func TestCurlFail(t *testing.T) {
	f := newFakeNet(t)
	const url = "http://public.test/status?code=404"
	check(t, f, []string{url}, want{exitOK, "status body", ""})
	check(t, f, []string{"-f", url}, want{exitHTTPReturned, "", "curl: (22) The requested URL returned error: 404\n"})
	check(t, f, []string{"-sf", url}, want{exitHTTPReturned, "", ""})
	check(t, f, []string{"-sSf", url}, want{exitHTTPReturned, "", "curl: (22) The requested URL returned error: 404\n"})
	check(t, f, []string{"--fail-with-body", url}, want{exitHTTPReturned, "status body", "curl: (22) The requested URL returned error: 404\n"})
	check(t, f, []string{"-f", "http://public.test/status?code=399"}, want{exitOK, "status body", ""})
	// The failed request wins over a binary body, which isn't written.
	check(t, f, []string{"--fail-with-body", "http://public.test/binary?code=404"}, want{exitHTTPReturned, "", "curl: (22) The requested URL returned error: 404\n"})
}

// A request the policy refuses exits 2 with the reason, even under -s.
func TestCurlPolicyRefusals(t *testing.T) {
	f := newFakeNet(t)
	tests := []struct {
		url, want string
	}{
		{"http://denied.test/", "host denied.test is in deny_hosts"},
		{"https://127.0.0.1/", "address 127.0.0.1 is not public"},
		{"file:///etc/passwd", `protocol "file" is not supported: kuzl only fetches http and https`},
		{"http://u:p@public.test/", "credentials in the URL are not supported"},
	}
	for _, tt := range tests {
		check(t, f, []string{"-s", tt.url}, want{exitUsage, "", "curl: " + tt.want + "\n"})
	}
	if n := f.requests.Load(); n != 0 {
		t.Errorf("%d requests sent, want none", n)
	}
}

func TestCurlNetworkErrors(t *testing.T) {
	f := newFakeNet(t)
	check(t, f, []string{"http://nxdomain.test/"}, want{exitCouldntResolve, "", "curl: (6) Could not resolve host: nxdomain.test\n"})
	check(t, f, []string{"-s", "http://nxdomain.test/"}, want{exitCouldntResolve, "", ""})
	check(t, f, []string{"http://down.test/"}, want{exitCouldntConnect, "", "curl: (7) Failed to connect: connection refused\n"})

	code, stdout, stderr := f.curl(t, "-m", "0.2", "http://public.test/slow")
	if code != exitTimeout || stdout != "" || !strings.HasPrefix(stderr, "curl: (28) Operation timed out after ") {
		t.Errorf("-m: got (%d, %q, %q), want exit 28", code, stdout, stderr)
	}
	// --connect-timeout covers the name lookup too.
	code, stdout, stderr = f.curl(t, "--connect-timeout", "0.2", "http://slowdns.test/")
	if code != exitTimeout || stdout != "" || !strings.HasPrefix(stderr, "curl: (28) Connection timed out after ") {
		t.Errorf("--connect-timeout: got (%d, %q, %q), want exit 28", code, stdout, stderr)
	}
}

// With no policy built in, the cap is config.DefaultMaxStdoutBytes.
func TestCurlCapsStdout(t *testing.T) {
	f := newFakeNet(t)
	limit := config.DefaultMaxStdoutBytes
	all := strings.Repeat("b", limit)
	n := strconv.Itoa(limit)
	for _, q := range []string{"n=" + strconv.Itoa(limit+5), "n=" + strconv.Itoa(limit+5) + "&chunked=1"} {
		check(t, f, []string{"http://public.test/big?" + q}, want{exitOK, all, "… truncated, 5 more bytes; use -o to save it all\n"})
	}
	check(t, f, []string{"http://public.test/big?n=" + n + "&chunked=1"}, want{exitOK, all, ""})
	// The cut falls on a character boundary: é is two bytes, and the last one
	// the cap allows is its first.
	s := "x" + strings.Repeat("é", limit/2)
	check(t, f, []string{"http://public.test/big?n=3&s=" + s}, want{exitOK, s[:limit-1], "… truncated, 5 more bytes; use -o to save it all\n"})

	// Headers count towards the cap.
	code, stdout, stderr := f.curl(t, "-i", "http://public.test/big?n="+n)
	if code != exitOK || len(stdout) != limit || !strings.HasPrefix(stdout, "HTTP/1.1 200 OK\r\n") ||
		!strings.HasPrefix(stderr, "… truncated, ") {
		t.Errorf("-i: got (%d, %d bytes, %q)", code, len(stdout), stderr)
	}
	if code, stdout, _ := f.curl(t, "--help"); code != exitOK || !strings.Contains(stdout, "Stdout stops after "+n+" bytes,") {
		t.Errorf("--help: got (%d, %q), want the cap in it", code, clip(stdout))
	}
}

// The policy's max_stdout_bytes, as IO.MaxStdoutBytes stands in for it,
// sets the cap.
func TestCurlStdoutCapFromPolicy(t *testing.T) {
	f := newFakeNet(t)
	var out, errOut bytes.Buffer
	s := f.io(t, &out, &errOut, nil)
	s.MaxStdoutBytes = 10
	code := Run([]string{"curl", "http://public.test/big?n=12"}, s)
	if code != exitOK || out.String() != "bbbbbbbbbb" || errOut.String() != "… truncated, 2 more bytes; use -o to save it all\n" {
		t.Errorf("got (%d, %q, %q), want 10 bytes and the note", code, out.String(), errOut.String())
	}
	out.Reset()
	if code := Run([]string{"curl", "--help"}, s); code != exitOK || !strings.Contains(out.String(), "Stdout stops after 10 bytes,") {
		t.Errorf("--help: got (%d, %q), want the cap in it", code, clip(out.String()))
	}
}

func TestCurlRefusesBinaryOnStdout(t *testing.T) {
	f := newFakeNet(t)
	check(t, f, []string{"-s", "http://public.test/binary"}, want{exitWriteError, "", "curl: (23) binary output (Content-Type image/png) is not written to stdout; use -o to save it\n"})
	check(t, f, []string{"http://public.test/latin1"}, want{exitWriteError, "", "curl: (23) binary output (Content-Type text/plain; charset=utf-8) is not written to stdout; use -o to save it\n"})
	// The headers still come out with -i.
	code, stdout, _ := f.curl(t, "-i", "http://public.test/binary")
	if code != exitWriteError || !strings.HasPrefix(stdout, "HTTP/1.1 200 OK\r\n") || !strings.HasSuffix(stdout, "\r\n\r\n") {
		t.Errorf("-i: got (%d, %q), want the headers and exit 23", code, stdout)
	}
}

// brokenPipe is a stdout whose reader has gone away.
type brokenPipe struct{}

func (brokenPipe) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

// A stdout that can't be written exits 23, as curl does, for the body and for
// the headers that -i writes before a binary body.
func TestCurlReportsWriteErrors(t *testing.T) {
	f := newFakeNet(t)
	for _, args := range [][]string{{"http://public.test/"}, {"-i", "http://public.test/binary"}} {
		var errOut bytes.Buffer
		code := Run(append([]string{"curl"}, args...), f.io(t, brokenPipe{}, &errOut, nil))
		if want := "curl: (23) Failure writing output to destination: broken pipe\n"; code != exitWriteError || errOut.String() != want {
			t.Errorf("curl %s: got (%d, %q), want (%d, %q)", strings.Join(args, " "), code, errOut.String(), exitWriteError, want)
		}
	}
}

// The record has the host, the method, the status and the byte count, never
// the path, the query or a header.
func TestCurlLogsRequestWithoutSecrets(t *testing.T) {
	f := newFakeNet(t)
	var logged bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logged, nil))
	s := f.io(t, &bytes.Buffer{}, &bytes.Buffer{}, log)
	Run([]string{"curl", "-H", "Authorization: Bearer SEKRET", "http://public.test/big?n=7&token=SEKRET"}, s)

	var rec map[string]any
	if err := json.Unmarshal(logged.Bytes(), &rec); err != nil {
		t.Fatalf("log = %q, want one JSON record: %v", logged.String(), err)
	}
	if rec["host"] != "public.test" || rec["method"] != "GET" || rec["status"] != float64(200) ||
		rec["bytes"] != float64(7) || fmt.Sprint(rec["flags"]) != "[header]" {
		t.Errorf("record = %v", rec)
	}
	if strings.Contains(logged.String(), "SEKRET") || strings.Contains(logged.String(), "/big") {
		t.Errorf("log = %q, want no path, query or header", logged.String())
	}

	// Nor the name of the -o file.
	logged.Reset()
	Run([]string{"curl", "-o", "SEKRET.txt", "http://public.test/"}, s)
	if !strings.Contains(logged.String(), `"output"`) || strings.Contains(logged.String(), "SEKRET") {
		t.Errorf("log = %q, want the flag name only", logged.String())
	}
}

// wantFile checks that name, under f's root, holds content.
func (f *fakeNet) wantFile(t *testing.T, name, content string) {
	t.Helper()
	got, err := os.ReadFile(filepath.Join(f.root, name)) //nolint:gosec // G304: a path under the test temp dir.
	if err != nil || string(got) != content {
		t.Errorf("%s = %q, %v; want %q", name, clip(string(got)), err, clip(content))
	}
}

func (f *fakeNet) wantNoFile(t *testing.T, name string) {
	t.Helper()
	if _, err := os.Lstat(filepath.Join(f.root, name)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("%s: %v, want no such file", name, err)
	}
}

func TestCurlOutput(t *testing.T) {
	f := newFakeNet(t)
	check(t, f, []string{"-o", "out.txt", "http://public.test/"}, want{exitOK, "", ""})
	f.wantFile(t, "out.txt", "hello from public.test")
	// Binary bodies, and bodies over the stdout cap, go to a file whole, and
	// missing directories are made.
	check(t, f, []string{"-o", "sub/dir/b.png", "http://public.test/binary"}, want{exitOK, "", ""})
	f.wantFile(t, "sub/dir/b.png", "\x89PNG\r\n\x1a\n\x00\x00")
	check(t, f, []string{"--create-dirs", "-o", filepath.Join(f.root, "big.txt"), "http://public.test/big?n=200000&chunked=1"}, want{exitOK, "", ""})
	f.wantFile(t, "big.txt", strings.Repeat("b", 200000))
	// -i and -I put the headers in the file, as curl does.
	check(t, f, []string{"-i", "-o", "head.txt", "http://public.test/"}, want{exitOK, "", ""})
	got, _ := os.ReadFile(filepath.Join(f.root, "head.txt")) //nolint:gosec // G304: a path under the test temp dir.
	if !bytes.HasPrefix(got, []byte("HTTP/1.1 200 OK\r\n")) || !bytes.HasSuffix(got, []byte("\r\n\r\nhello from public.test")) {
		t.Errorf("-i -o wrote %q, want the headers and the body", got)
	}
	// - is stdout.
	check(t, f, []string{"-o", "-", "http://public.test/"}, want{exitOK, "hello from public.test", ""})

	// -O takes the last segment of the URL as given, not decoded and without
	// the query.
	check(t, f, []string{"-O", "http://public.test/dl/name.txt?x=1"}, want{exitOK, "", ""})
	f.wantFile(t, "name.txt", "hello from public.test")
	check(t, f, []string{"-O", "http://public.test/a%2Fb.txt"}, want{exitOK, "", ""})
	f.wantFile(t, "a%2Fb.txt", "hello from public.test")
	// A redirect doesn't rename the file.
	check(t, f, []string{"-LO", "http://public.test/to?u=http://sub.public.test/other.txt"}, want{exitOK, "", ""})
	f.wantFile(t, "to", "hello from sub.public.test")
	f.wantNoFile(t, "other.txt")
}

func TestCurlOutputFail(t *testing.T) {
	f := newFakeNet(t)
	const url = "http://public.test/status?code=404"
	// -f writes no file; --fail-with-body writes the body, as curl does.
	check(t, f, []string{"-f", "-o", "f.txt", url}, want{exitHTTPReturned, "", "curl: (22) The requested URL returned error: 404\n"})
	f.wantNoFile(t, "f.txt")
	check(t, f, []string{"--fail-with-body", "-o", "f.txt", url}, want{exitHTTPReturned, "", "curl: (22) The requested URL returned error: 404\n"})
	f.wantFile(t, "f.txt", "status body")
}

// A file outside the root is refused before anything is sent.
func TestCurlOutputRefusals(t *testing.T) {
	f := newFakeNet(t)
	hint := "Run 'curl --help' for usage.\n"
	outside := filepath.Join(filepath.Dir(f.root), "out.txt")
	check(t, f, []string{"-o", "../out.txt", "http://public.test/"}, want{exitUsage, "", "curl: -o ../out.txt: outside " + f.root + "\n"})
	check(t, f, []string{"-so", outside, "http://public.test/"}, want{exitUsage, "", "curl: -o " + outside + ": outside " + f.root + "\n"})
	check(t, f, []string{"-O", "http://public.test/a/.."}, want{exitUsage, "", "curl: -O ..: outside " + f.root + "\n"})
	check(t, f, []string{"-O", "http://public.test/"}, want{exitWriteError, "", "curl: (23) Remote file name has no length\n"})
	check(t, f, []string{"-o", "x", "-O", "http://public.test/x"}, want{exitUsage, "", "curl: use -o or -O, not both\n" + hint})
	check(t, f, []string{"-o", "", "http://public.test/"}, want{exitUsage, "", "curl: -o \"\": want a file name, or - for stdout\n" + hint})
	if n := f.requests.Load(); n != 0 {
		t.Errorf("%d requests sent, want none", n)
	}

	// A symlink is found when the file is opened, after the request.
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(f.root, "link")); err != nil {
		t.Fatal(err)
	}
	check(t, f, []string{"-o", "link", "http://public.test/"}, want{exitWriteError, "", "curl: (23) Failed to open the file link: not a regular file\n"})
	if got, _ := os.ReadFile(secret); string(got) != "key" { //nolint:gosec // G304: a path under the test temp dir.
		t.Errorf("secret = %q, want it untouched", got)
	}
}

func TestCurlMaxFilesize(t *testing.T) {
	f := newFakeNet(t)
	const tooBig = "curl: (63) Maximum file size exceeded\n"
	// With a Content-Length or without, nothing is written to stdout.
	check(t, f, []string{"--max-filesize", "10", "http://public.test/big?n=11"}, want{exitFileSizeExceeded, "", tooBig})
	check(t, f, []string{"--max-filesize", "10", "http://public.test/big?n=11&chunked=1"}, want{exitFileSizeExceeded, "", tooBig})
	check(t, f, []string{"-s", "--max-filesize", "10", "http://public.test/big?n=11"}, want{exitFileSizeExceeded, "", ""})
	check(t, f, []string{"--max-filesize", "10", "http://public.test/big?n=10&chunked=1"}, want{exitOK, "bbbbbbbbbb", ""})
	check(t, f, []string{"--max-filesize", "1k", "http://public.test/big?n=1024&chunked=1"}, want{exitOK, strings.Repeat("b", 1024), ""})
	// Past the stdout cap, it is the whole body that counts.
	limit := config.DefaultMaxStdoutBytes
	big := "http://public.test/big?n=" + strconv.Itoa(limit+2) + "&chunked=1"
	check(t, f, []string{"--max-filesize", strconv.Itoa(limit + 1), big}, want{exitFileSizeExceeded, "", tooBig})
	check(t, f, []string{"--max-filesize", strconv.Itoa(limit + 2), big},
		want{exitOK, strings.Repeat("b", limit), "… truncated, 2 more bytes; use -o to save it all\n"})

	// -o: a Content-Length over the limit writes no file; a body without one
	// stops at the limit and leaves what was written.
	check(t, f, []string{"--max-filesize", "10", "-o", "cl.txt", "http://public.test/big?n=11"}, want{exitFileSizeExceeded, "", tooBig})
	f.wantNoFile(t, "cl.txt")
	check(t, f, []string{"--max-filesize", "10", "-o", "chunked.txt", "http://public.test/big?n=11&chunked=1"}, want{exitFileSizeExceeded, "", tooBig})
	f.wantFile(t, "chunked.txt", "bbbbbbbbbb")
	check(t, f, []string{"--max-filesize", "10", "-o", "ok.txt", "http://public.test/big?n=10&chunked=1"}, want{exitOK, "", ""})
	f.wantFile(t, "ok.txt", "bbbbbbbbbb")

	hint := "Run 'curl --help' for usage.\n"
	for _, v := range []string{"", "1x", "-1", "k", "9223372036854775807k"} {
		check(t, f, []string{"--max-filesize", v, "http://public.test/"}, want{exitUsage, "", fmt.Sprintf("curl: --max-filesize %q: want a number of bytes, with k, M or G or without\n", v) + hint})
	}
	check(t, f, []string{"--max-filesize", "101M", "http://public.test/"}, want{exitUsage, "", "curl: --max-filesize 101M: kuzl downloads at most 100M\n" + hint})
}

func TestParseSize(t *testing.T) {
	for s, want := range map[string]int64{"0": 0, "10": 10, "2k": 2 << 10, "3K": 3 << 10, "1M": 1 << 20, "1g": 1 << 30} {
		if got, ok := parseSize(s); !ok || got != want {
			t.Errorf("parseSize(%q) = %d, %v; want %d", s, got, ok, want)
		}
	}
}

func TestCurlRange(t *testing.T) {
	f := newFakeNet(t)
	const url = "http://public.test/headers"
	for _, r := range []string{"0-499", "500-", "-500", "0-0,-1"} {
		check(t, f, []string{"-r", r, url}, want{exitOK, "Accept=[\"*/*\"]\nUser-Agent=[\"kuzl/dev\"]\nRange=[\"bytes=" + r + "\"]\nmethod=GET\n", ""})
	}
	// -H comes last, as for the other headers.
	check(t, f, []string{"-r", "1-2", "-H", "Range: bytes=5-", url}, want{exitOK, "Accept=[\"*/*\"]\nUser-Agent=[\"kuzl/dev\"]\nRange=[\"bytes=5-\"]\nmethod=GET\n", ""})
	hint := "Run 'curl --help' for usage.\n"
	for _, r := range []string{"abc", "-", "1-2,", "bytes=1-2"} {
		check(t, f, []string{"-r", r, url}, want{exitUsage, "", fmt.Sprintf("curl: -r %q: want byte ranges, as in 0-499, 500- or -500\n", r) + hint})
	}
}

func TestCurlWriteOut(t *testing.T) {
	f := newFakeNet(t)
	check(t, f, []string{"-w", `\n%{http_code} %{content_type}\n`, "http://public.test/status?code=404"},
		want{exitOK, "status body\n404 text/plain; charset=utf-8\n", ""})
	// The size is the body's, and the URL the last hop's.
	check(t, f, []string{"-L", "-o", "out.txt", "-w", `%{size_download}\t%{url_effective}`, "http://public.test/to?u=http://sub.public.test/x"},
		want{exitOK, "26\thttp://sub.public.test/x", ""})
	check(t, f, []string{"-w", `100%% %{http_code}`, "-o", "out.txt", "http://public.test/"}, want{exitOK, `100% 200`, ""})
	// As in curl, only \n, \r and \t are escapes: \\, \x and a \ at the end
	// are written as they are.
	check(t, f, []string{"-w", `\\ \x \`, "-o", "out.txt", "http://public.test/"}, want{exitOK, `\\ \x \`, ""})
	// It comes after a failed transfer too, as curl's does, but not after a
	// refusal, where nothing was sent.
	check(t, f, []string{"-sf", "-w", "%{http_code}", "http://public.test/status?code=404"}, want{exitHTTPReturned, "404", ""})
	check(t, f, []string{"-s", "-w", "%{http_code}", "http://nxdomain.test/"}, want{exitCouldntResolve, "000", ""})
	// A transfer that fails after a response reports that response.
	check(t, f, []string{"-sL", "--max-redirs", "0", "-w", "%{http_code} %{url_effective}", "http://public.test/to?u=http://sub.public.test/x"},
		want{exitTooManyRedirects, "302 http://public.test/to?u=http://sub.public.test/x", ""})
	check(t, f, []string{"-s", "-w", "%{http_code}", "http://denied.test/"}, want{exitUsage, "", "curl: host denied.test is in deny_hosts\n"})

	hint := "Run 'curl --help' for usage.\n"
	check(t, f, []string{"-w", "@fmt.txt", "http://public.test/"}, want{exitUsage, "", "curl: -w @file is not supported: kuzl reads no local files\n"})
	check(t, f, []string{"-w", "%{time_total}", "http://public.test/"},
		want{exitUsage, "", "curl: -w: unknown variable %{time_total}: kuzl knows %{http_code}, %{content_type}, %{url_effective}, %{size_download}\n" + hint})
	check(t, f, []string{"-w", "%{http_code", "http://public.test/"}, want{exitUsage, "", "curl: -w: \"%{\" without a closing \"}\"\n" + hint})
}

func TestCurlGetQuery(t *testing.T) {
	f := newFakeNet(t)
	const url = "http://public.test/query"
	tests := []struct {
		args []string
		want string
	}{
		{[]string{"-G"}, "GET "},
		{[]string{"-G", "-d", "a=1", "-d", "b=2"}, "GET a=1&b=2"},
		// After the URL's own query; the fragment still isn't sent.
		{[]string{"-G", "-d", "a=1", url + "?x=1#frag"}, "GET x=1&a=1"},
		{[]string{"-G", "-d", "a=1", url + "?"}, "GET a=1"},
		// -d is sent as given, but for the bytes a query can't hold.
		{[]string{"-G", "-d", "q=a+b%20c", "-d", "r=a b#c\né"}, "GET q=a+b%20c&r=a%20b%23c%0A%C3%A9"},
		// --data-urlencode encodes what follows the first =, all of it without
		// one.
		{[]string{"-G", "--data-urlencode", "q=a b&c=d+e/é", "--data-urlencode", "=x y", "--data-urlencode", "x y"}, "GET q=a%20b%26c%3Dd%2Be%2F%C3%A9&x%20y&x%20y"},
		{[]string{"-G", "--data-urlencode", "mail=a@b.test"}, "GET mail=a%40b.test"},
		// The flags keep the command line's order, as curl's do, and
		// --data-raw takes @ as is.
		{[]string{"-d", "a=1", "--data-urlencode", "b=c d", "--data-raw", "@e", "-G", "--data-ascii", "f", "--data-binary", "g"}, "GET a=1&b=c%20d&@e&f&g"},
	}
	for _, tt := range tests {
		args := tt.args
		if !strings.HasPrefix(args[len(args)-1], "http") {
			args = append(args, url)
		}
		check(t, f, args, want{exitOK, tt.want, ""})
	}
	// With -I, HEAD: the query is in the URL it went to.
	check(t, f, []string{"-IG", "-d", "a=1", "-o", "head.txt", "-w", "%{url_effective}", url}, want{exitOK, url + "?a=1", ""})
}

// No data flag reads a file, with -G or without.
func TestCurlGetQueryRefusals(t *testing.T) {
	f := newFakeNet(t)
	const url = "http://public.test/query"
	tests := []struct {
		args []string
		want string
	}{
		{[]string{"-G", "-d", "@/home/app/.aws/credentials"}, "-d @file is not supported: kuzl reads no local files"},
		{[]string{"-sG", "--data-binary", "@x"}, "--data-binary @file is not supported: kuzl reads no local files"},
		{[]string{"-G", "--data-ascii", "@x"}, "--data-ascii @file is not supported: kuzl reads no local files"},
		{[]string{"-G", "-d", "a=1", "--data-urlencode", "@x"}, `--data-urlencode "@x" is not supported: kuzl reads no local files; write name=content to send an @`},
		{[]string{"-G", "--data-urlencode", "name@x"}, `--data-urlencode "name@x" is not supported: kuzl reads no local files; write name=content to send an @`},
	}
	for _, tt := range tests {
		check(t, f, append(tt.args, url), want{exitUsage, "", "curl: " + tt.want + "\n"})
	}
	// Without a URL too.
	check(t, f, []string{"-G", "-d", "@x"}, want{exitUsage, "", "curl: -d @file is not supported: kuzl reads no local files\n"})
	if n := f.requests.Load(); n != 0 {
		t.Errorf("%d requests sent, want none", n)
	}
}

func TestEscape(t *testing.T) {
	const all = " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~\x00\x7fé"
	if got, want := escapeAll(all), "%20%21%22%23%24%25%26%27%28%29%2A%2B%2C-.%2F%3A%3B%3C%3D%3E%3F%40%5B%5C%5D%5E_%60%7B%7C%7D~%00%7F%C3%A9"; got != want {
		t.Errorf("escapeAll = %q, want %q", got, want)
	}
	if got, want := escapeQuery(all), "%20!%22%23$%&'()*+,-./:;%3C=%3E?@%5B%5C%5D%5E_%60%7B%7C%7D~%00%7F%C3%A9"; got != want {
		t.Errorf("escapeQuery = %q, want %q", got, want)
	}
}
