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
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/evadcmd/kuzl/internal/netguard"
)

// fakeNet stands in for DNS and the network, as netguard's tests do: names
// resolve from hosts, and every dial reaches the one loopback test server,
// which tells the virtual hosts apart by the Host header.
type fakeNet struct {
	server   string
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
			for _, h := range []string{"Accept", "User-Agent", "Referer", "Authorization", "X-A", "X-Empty"} {
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
		default:
			_, _ = io.WriteString(w, "hello from "+r.Host) //nolint:gosec // G705: a plain-text echo for the test.
		}
	}))
	t.Cleanup(srv.Close)
	f.server = srv.Listener.Addr().String()
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
		{[]string{"-d", "@/home/app/.aws/credentials"}, "-d/--data is not supported: kuzl only sends GET and HEAD"},
		{[]string{"-s", "--data-binary=x"}, "--data-binary is not supported: kuzl only sends GET and HEAD"},
		{[]string{"-dx"}, "-d/--data is not supported: kuzl only sends GET and HEAD"},
		{[]string{"--json", "{}"}, "--json is not supported: kuzl only sends GET and HEAD"},
		{[]string{"-F", "f=@x"}, "-F/--form is not supported: kuzl only sends GET and HEAD"},
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
	check(t, f, []string{"-d", "x"}, want{exitUsage, "", "curl: -d/--data is not supported: kuzl only sends GET and HEAD\n"})
	check(t, f, []string{"-X", "PUT"}, want{exitUsage, "", "curl: -X PUT is not supported: kuzl only sends GET and HEAD\n"})
	if n := f.requests.Load(); n != 0 {
		t.Errorf("%d requests sent, want none", n)
	}
	// The refused flags stay out of the help.
	_, stdout, _ := f.curl(t, "--help")
	if strings.Contains(stdout, "--data") || strings.Contains(stdout, "--proxy") {
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

func TestCurlCapsStdout(t *testing.T) {
	f := newFakeNet(t)
	all := strings.Repeat("b", maxShowBytes)
	for _, q := range []string{"n=100005", "n=100005&chunked=1"} {
		check(t, f, []string{"http://public.test/big?" + q}, want{exitOK, all, "… truncated, 5 more bytes\n"})
	}
	check(t, f, []string{"http://public.test/big?n=100000&chunked=1"}, want{exitOK, all, ""})
	// The cut falls on a character boundary: é is two bytes, and the 100000th
	// is its first.
	s := "x" + strings.Repeat("é", maxShowBytes/2)
	check(t, f, []string{"http://public.test/big?n=3&s=" + s}, want{exitOK, s[:maxShowBytes-1], "… truncated, 5 more bytes\n"})

	// Headers count towards the cap.
	code, stdout, stderr := f.curl(t, "-i", "http://public.test/big?n=100000")
	if code != exitOK || len(stdout) != maxShowBytes || !strings.HasPrefix(stdout, "HTTP/1.1 200 OK\r\n") ||
		!strings.HasPrefix(stderr, "… truncated, ") {
		t.Errorf("-i: got (%d, %d bytes, %q)", code, len(stdout), stderr)
	}
}

func TestCurlRefusesBinaryOnStdout(t *testing.T) {
	f := newFakeNet(t)
	check(t, f, []string{"-s", "http://public.test/binary"}, want{exitWriteError, "", "curl: (23) binary output (Content-Type image/png) is not written to stdout\n"})
	check(t, f, []string{"http://public.test/latin1"}, want{exitWriteError, "", "curl: (23) binary output (Content-Type text/plain; charset=utf-8) is not written to stdout\n"})
	// The headers still come out with -i.
	code, stdout, _ := f.curl(t, "-i", "http://public.test/binary")
	if code != exitWriteError || !strings.HasPrefix(stdout, "HTTP/1.1 200 OK\r\n") || !strings.HasSuffix(stdout, "\r\n\r\n") {
		t.Errorf("-i: got (%d, %q), want the headers and exit 23", code, stdout)
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
}
