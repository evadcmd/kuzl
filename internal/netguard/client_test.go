package netguard

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeNet stands in for DNS and the network: names resolve from its table,
// and every dial reaches the one loopback test server, which tells the
// virtual hosts apart by the Host header. It records what was dialed.
type fakeNet struct {
	hosts  map[string][]string
	server string // the test server's host:port

	mu     sync.Mutex
	dialed []string
}

func (f *fakeNet) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	// As DNS does, ignoring case and a trailing dot.
	addrs, ok := f.hosts[strings.TrimSuffix(strings.ToLower(host), ".")]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	var ips []netip.Addr
	for _, a := range addrs {
		ips = append(ips, netip.MustParseAddr(a))
	}
	return ips, nil
}

func (f *fakeNet) dial(ctx context.Context, network, address string) (net.Conn, error) {
	f.mu.Lock()
	f.dialed = append(f.dialed, address)
	f.mu.Unlock()
	if strings.HasPrefix(address, "1.1.1.1:") {
		return nil, &net.OpError{Op: "dial", Net: network, Err: errors.New("connection refused")}
	}
	var d net.Dialer
	return d.DialContext(ctx, network, f.server)
}

func (f *fakeNet) dials() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.dialed...)
}

// newFakeNet starts a server for the virtual hosts below:
//   - /to?u=URL redirects to URL;
//   - /loop redirects to itself;
//   - /headers echoes the Authorization, Cookie and X-Trace headers.
func newFakeNet(t *testing.T) *fakeNet {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/to":
			http.Redirect(w, r, r.URL.Query().Get("u"), http.StatusFound) //nolint:gosec // G710: the open redirect is what the test needs.
		case "/loop":
			http.Redirect(w, r, "/loop", http.StatusFound)
		case "/headers":
			_, _ = io.WriteString(w, r.Host+" auth="+r.Header.Get("Authorization")+ //nolint:gosec // G705: a plain-text echo for the test.
				" cookie="+r.Header.Get("Cookie")+" trace="+r.Header.Get("X-Trace"))
		default:
			_, _ = io.WriteString(w, "hello from "+r.Host) //nolint:gosec // G705: a plain-text echo for the test.
		}
	}))
	t.Cleanup(srv.Close)
	return &fakeNet{
		server: srv.Listener.Addr().String(),
		hosts: map[string][]string{
			"public.test":     {"8.8.8.8"},
			"sub.public.test": {"8.8.4.4"},
			"other.test":      {"9.9.9.9"},
			"denied.test":     {"8.8.8.8"},
			"loopback.test":   {"127.0.0.1"},
			"metadata.test":   {"169.254.169.254"},
			"mapped.test":     {"::ffff:10.0.0.1"},
			"mixed.test":      {"10.0.0.1", "::1", "8.8.8.8"},
			"down.test":       {"1.1.1.1"},
			"downlocal.test":  {"127.0.0.1", "1.1.1.1"},
			"empty.test":      {},
			"banned.test":     {"1.0.0.1"},
			"banned64.test":   {"64:ff9b::100:1"}, // 1.0.0.1 through NAT64
			"partbanned.test": {"1.0.0.1", "8.8.8.8"},
		},
	}
}

func (f *fakeNet) client(t *testing.T, o Options) *http.Client {
	t.Helper()
	return mustPolicy(t, []string{"*"}, []string{"denied.test"}, "1.0.0.0/24").client(o, f, f.dial)
}

func get(c *http.Client, url string, header ...string) (string, int, error) {
	req, err := http.NewRequest(http.MethodGet, url, http.NoBody)
	if err != nil {
		return "", 0, err
	}
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	return string(body), resp.StatusCode, err
}

func follow(n int) Options { return Options{FollowRedirects: true, MaxRedirects: n} }

func TestClientDialsOnlyPublicAddresses(t *testing.T) {
	tests := []struct {
		host   string
		dialed []string
		want   string // the refusal, or "" to succeed
	}{
		{"public.test", []string{"8.8.8.8:80"}, ""},
		{"loopback.test", nil, "host loopback.test has no address kuzl may dial: 127.0.0.1 is not public"},
		{"metadata.test", nil, "not public"},
		{"mapped.test", nil, "not public"},
		// Only the public address of a mixed answer is dialed.
		{"mixed.test", []string{"8.8.8.8:80"}, ""},
		// deny_addrs holds for names too, on the address they resolve to.
		{"banned.test", nil, "host banned.test has no address kuzl may dial: 1.0.0.1 is in deny_addrs"},
		{"banned64.test", nil, "64:ff9b::100:1 is in deny_addrs"},
		{"partbanned.test", []string{"8.8.8.8:80"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			f := newFakeNet(t)
			body, _, err := get(f.client(t, Options{}), "http://"+tt.host+"/")
			wantRefused(t, err, tt.want)
			if tt.want == "" && body != "hello from "+tt.host {
				t.Errorf("body = %q", body)
			}
			if got := f.dials(); strings.Join(got, ",") != strings.Join(tt.dialed, ",") {
				t.Errorf("dialed %v, want %v", got, tt.dialed)
			}
		})
	}
}

func TestClientReportsNetworkErrors(t *testing.T) {
	f := newFakeNet(t)
	c := f.client(t, Options{})
	for _, host := range []string{"nxdomain.test", "empty.test"} {
		_, _, err := get(c, "http://"+host+"/")
		if de, ok := errors.AsType[*net.DNSError](err); !ok || !de.IsNotFound {
			t.Errorf("%s: err = %v, want a not-found *net.DNSError", host, err)
		}
	}
	// A failed connection to a public address is reported as such, even
	// when the name also had a refused one.
	for _, host := range []string{"down.test", "downlocal.test"} {
		_, _, err := get(c, "http://"+host+"/")
		if _, ok := errors.AsType[*net.OpError](err); !ok || isRefused(err) {
			t.Errorf("%s: err = %v, want a *net.OpError", host, err)
		}
	}
}

func isRefused(err error) bool {
	_, ok := errors.AsType[*RefusedError](err)
	return ok
}

// The policy is checked in the transport, so the first request and every
// redirect hop go through it, and nothing refused is dialed.
func TestClientChecksEveryRequest(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"http://denied.test/", "host denied.test is in deny_hosts"},
		{"https://127.0.0.1/", "not public"},
		{"http://public.test/to?u=http://other.test/", ""},
		{"http://public.test/to?u=http://denied.test/", "host denied.test is in deny_hosts"},
		{"http://public.test/to?u=http://DENIED.test./", "host denied.test is in deny_hosts"},
		{"http://public.test/to?u=http://127.0.0.1:8080/", "address 127.0.0.1 is not public"},
		{"http://public.test/to?u=http://loopback.test/", "not public"},
		{"http://public.test/to?u=http://[::ffff:169.254.169.254]/", "not public"},
		{"http://public.test/to?u=file:///etc/passwd", `protocol "file"`},
		{"http://public.test/to?u=http://u:p@other.test/", "credentials"},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			f := newFakeNet(t)
			body, _, err := get(f.client(t, follow(10)), tt.url)
			wantRefused(t, err, tt.want)
			if tt.want == "" && body != "hello from other.test" {
				t.Errorf("body = %q", body)
			}
			for _, d := range f.dials() {
				if d != "8.8.8.8:80" && d != "9.9.9.9:80" {
					t.Errorf("dialed %s", d)
				}
			}
		})
	}
}

func TestClientRefusesAnotherHostHeader(t *testing.T) {
	f := newFakeNet(t)
	req, err := http.NewRequest(http.MethodGet, "http://public.test/", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "denied.test"
	_, err = f.client(t, Options{}).Do(req)
	wantRefused(t, err, "Host header")
	if d := f.dials(); len(d) != 0 {
		t.Errorf("dialed %v", d)
	}
}

// The client finds CloseIdleConnections on its transport, so checkedTransport
// has to pass it on, or idle connections stay open until IdleConnTimeout.
func TestClientClosesIdleConnections(t *testing.T) {
	closed := make(chan struct{}, 1)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "hello")
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateClosed {
			closed <- struct{}{}
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)
	f := &fakeNet{server: srv.Listener.Addr().String(), hosts: map[string][]string{"public.test": {"8.8.8.8"}}}
	c := f.client(t, Options{})
	if _, _, err := get(c, "http://public.test/"); err != nil {
		t.Fatal(err)
	}
	c.CloseIdleConnections()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Error("the idle connection is still open")
	}
}

func TestClientRedirects(t *testing.T) {
	f := newFakeNet(t)
	// Not following, the redirect is the response.
	_, code, err := get(f.client(t, Options{MaxRedirects: 10}), "http://public.test/loop")
	if err != nil || code != http.StatusFound {
		t.Errorf("without FollowRedirects: %d, %v; want 302", code, err)
	}

	// curl's --max-redirs N follows N redirects and fails on the next.
	for _, max := range []int{0, 1, 3} {
		_, _, err := get(f.client(t, follow(max)), "http://public.test/loop")
		if e, ok := errors.AsType[*TooManyRedirectsError](err); !ok || e.Max != max {
			t.Errorf("MaxRedirects %d: err = %v, want a *TooManyRedirectsError", max, err)
		}
		_, code, err = get(f.client(t, follow(max)), "http://public.test/"+strings.Repeat("to?u=/", max))
		if err != nil || code != http.StatusOK {
			t.Errorf("MaxRedirects %d with %d redirects: %d, %v; want 200", max, max, code, err)
		}
		_, _, err = get(f.client(t, follow(max)), "http://public.test/"+strings.Repeat("to?u=/", max+1))
		if _, ok := errors.AsType[*TooManyRedirectsError](err); !ok {
			t.Errorf("MaxRedirects %d with %d redirects: err = %v, want a *TooManyRedirectsError", max, max+1, err)
		}
	}
	// A negative limit is none, as curl's -1; 30 is past Go's default of 10.
	url := "http://public.test/" + strings.Repeat("to?u=/", 30)
	if _, code, err := get(f.client(t, follow(-1)), url); err != nil || code != http.StatusOK {
		t.Errorf("MaxRedirects -1: %d, %v; want 200", code, err)
	}
}

// Credentials set as headers stay with the first request's origin, as in
// curl; other headers follow the redirect.
func TestClientDropsCredentialsOffOrigin(t *testing.T) {
	headers := []string{"Authorization", "Bearer SEKRET", "Cookie", "s=SEKRET", "X-Trace", "t1"}
	tests := []struct {
		to   string
		want string
	}{
		{"/headers", "public.test auth=Bearer SEKRET cookie=s=SEKRET trace=t1"},
		{"http://PUBLIC.test/headers", "PUBLIC.test auth=Bearer SEKRET cookie=s=SEKRET trace=t1"},
		{"http://public.test:80/headers", "public.test:80 auth=Bearer SEKRET cookie=s=SEKRET trace=t1"},
		// Go's client compares the spelling, so a trailing dot drops them
		// too, which only ever sends less.
		{"http://public.test./headers", "public.test. auth= cookie= trace=t1"},
		// Go's client alone would keep them for a subdomain.
		{"http://sub.public.test/headers", "sub.public.test auth= cookie= trace=t1"},
		{"http://other.test/headers", "other.test auth= cookie= trace=t1"},
		{"http://public.test:8080/headers", "public.test:8080 auth= cookie= trace=t1"},
	}
	for _, tt := range tests {
		t.Run(tt.to, func(t *testing.T) {
			f := newFakeNet(t)
			body, _, err := get(f.client(t, follow(10)), "http://public.test/to?u="+tt.to, headers...)
			if err != nil || body != tt.want {
				t.Errorf("got %q, %v; want %q", body, err, tt.want)
			}
		})
	}
	// Back on the first origin, they stay dropped after a cross-domain hop:
	// Go's client keeps that drop for the rest of the chain (CVE-2024-45336).
	// After a subdomain hop, where only kuzl dropped them, they are sent
	// again there, as curl does (#8).
	f := newFakeNet(t)
	body, _, err := get(f.client(t, follow(10)), "http://public.test/to?u=http://other.test/to%3Fu=http://public.test/headers", headers...)
	if want := "public.test auth= cookie= trace=t1"; err != nil || body != want {
		t.Errorf("back on the first origin: %q, %v; want %q", body, err, want)
	}
	f = newFakeNet(t)
	body, _, err = get(f.client(t, follow(10)), "http://public.test/to?u=http://sub.public.test/to%3Fu=http://public.test/headers", headers...)
	if want := "public.test auth=Bearer SEKRET cookie=s=SEKRET trace=t1"; err != nil || body != want {
		t.Errorf("back on the first origin after a subdomain: %q, %v; want %q", body, err, want)
	}
}

// The real client, with the real resolver and dialer, can't reach the
// loopback test server under any name.
func TestRealClientRefusesLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("the test server was reached")
	}))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	c := mustPolicy(t, []string{"*"}, nil).Client(Options{})
	for _, host := range []string{"127.0.0.1", "[::ffff:127.0.0.1]", "localhost"} {
		_, _, err := get(c, "http://"+host+":"+port+"/")
		wantRefused(t, err, "not public")
	}
}

// The dialer's Control is a check of its own: dialing a loopback IP
// directly, past dialer, is refused before connecting.
func TestControlRefusesNonPublic(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	p := mustPolicy(t, nil, nil, "1.0.0.0/24")
	d := &net.Dialer{Control: p.control}
	_, err = d.DialContext(t.Context(), "tcp", ln.Addr().String())
	wantRefused(t, err, "address 127.0.0.1 is not public")

	for _, addr := range []string{"8.8.8.8:443", "[2606:4700::1111]:443"} {
		if err := p.control("tcp", addr, nil); err != nil {
			t.Errorf("control(%s) = %v, want nil", addr, err)
		}
	}
	for _, addr := range []string{"10.0.0.1:80", "[::1]:80", "[fe80::1%eth0]:80", "bogus", "1.0.0.1:443", "[::ffff:1.0.0.1]:443"} {
		if err := p.control("tcp", addr, nil); err == nil {
			t.Errorf("control(%s) = nil, want an error", addr)
		}
	}
}

// HTTP(S)_PROXY is ignored: through a proxy, only the proxy's address would
// be checked.
func TestClientIgnoresProxyEnv(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("http_proxy", "http://127.0.0.1:1")
	f := newFakeNet(t)
	body, _, err := get(f.client(t, Options{}), "http://public.test/")
	if err != nil || body != "hello from public.test" {
		t.Errorf("got %q, %v; want the direct response", body, err)
	}
}
