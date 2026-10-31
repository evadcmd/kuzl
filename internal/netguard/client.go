package netguard

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Options are the parts of a client the command line may choose. Nothing
// here can widen the policy.
type Options struct {
	// FollowRedirects makes the client follow redirects (curl's -L);
	// otherwise a redirect is returned as the response.
	FollowRedirects bool
	// MaxRedirects is how many redirects may be followed (curl's
	// --max-redirs); a negative number means no limit, as curl's -1 does.
	MaxRedirects int
	// ConnectTimeout bounds each connection attempt; zero means no bound.
	ConnectTimeout time.Duration
}

// TooManyRedirectsError is a redirect beyond Options.MaxRedirects.
type TooManyRedirectsError struct {
	Max int
}

func (e *TooManyRedirectsError) Error() string {
	return fmt.Sprintf("maximum (%d) redirects followed", e.Max)
}

// resolver is the part of *net.Resolver the dialer uses, so that tests can
// make names resolve to public addresses.
type resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// dialFunc dials an address that is already an IP and port.
type dialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// Client returns an http.Client that only sends requests p allows: every
// request, redirects included, is checked with CheckURL before it is sent,
// and only public addresses are dialed. HTTP(S)_PROXY is ignored: through a
// proxy, the address check would only see the proxy's.
//
// Errors from its Do wrap a *RefusedError for a refused request, a
// *TooManyRedirectsError, or what net reports, such as a *net.DNSError.
func (p *Policy) Client(o Options) *http.Client {
	d := &net.Dialer{Timeout: o.ConnectTimeout, Control: p.control}
	return p.client(o, net.DefaultResolver, d.DialContext)
}

func (p *Policy) client(o Options, r resolver, dial dialFunc) *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = nil
	t.DialContext = (&dialer{policy: p, resolve: r, dial: dial}).DialContext
	t.DialTLSContext = nil
	return &http.Client{
		Transport:     &checkedTransport{policy: p, next: t},
		CheckRedirect: checkRedirect(o),
	}
}

// checkedTransport checks each request before it is sent. The client calls
// it for every hop, so a redirect can't skip the check.
type checkedTransport struct {
	policy *Policy
	next   http.RoundTripper
}

func (t *checkedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := t.policy.CheckURL(req.URL); err != nil {
		return nil, err
	}
	// A Host header other than the URL's would send the request to a host
	// the lists never saw, on a shared front end.
	if req.Host != "" && req.Host != req.URL.Host {
		return nil, refused("a Host header other than the URL's is not supported")
	}
	return t.next.RoundTrip(req)
}

// CloseIdleConnections closes next's idle connections. The client's
// CloseIdleConnections only reaches a transport that has the method.
func (t *checkedTransport) CloseIdleConnections() {
	if c, ok := t.next.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}

// checkRedirect applies the redirect limit and drops credentials when a
// redirect leaves the first request's origin. curl drops Authorization and
// Cookie headers given with -H when the host, the port or the scheme changes
// (CVE-2022-27776) unless --location-trusted is set, which kuzl doesn't
// have. Go's client alone keeps them on a redirect to a subdomain.
func checkRedirect(o Options) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if !o.FollowRedirects {
			return http.ErrUseLastResponse
		}
		if o.MaxRedirects >= 0 && len(via) > o.MaxRedirects {
			return &TooManyRedirectsError{Max: o.MaxRedirects}
		}
		if !sameOrigin(via[0].URL, req.URL) {
			for _, h := range []string{"Authorization", "Cookie", "Proxy-Authorization"} {
				req.Header.Del(h)
			}
		}
		return nil
	}
}

func sameOrigin(a, b *url.URL) bool {
	return a.Scheme == b.Scheme && strings.EqualFold(a.Hostname(), b.Hostname()) && port(a) == port(b)
}

func port(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}

// dialer resolves the name itself and dials only the addresses it gets that
// the policy allows, by IP, so that the address checked is the one connected
// to and a second lookup can't return another (DNS rebinding).
type dialer struct {
	policy  *Policy
	resolve resolver
	dial    dialFunc
}

func (d *dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid port %q", portStr)
	}
	var ips []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		ips = []netip.Addr{ip}
	} else if ips, err = d.resolve.LookupNetIP(ctx, ipNetwork(network), host); err != nil {
		return nil, err
	}
	var refusals []string
	var dialErr error
	for _, ip := range ips {
		if why := d.policy.addrRefusal(ip); why != "" {
			refusals = append(refusals, ip.String()+" "+why)
			continue
		}
		conn, err := d.dial(ctx, network, netip.AddrPortFrom(ip, uint16(port)).String())
		if err == nil {
			return conn, nil
		}
		if dialErr == nil {
			dialErr = err
		}
		if ctx.Err() != nil {
			break
		}
	}
	if dialErr != nil {
		return nil, dialErr
	}
	if len(refusals) > 0 {
		return nil, refused("host %s has no address kuzl may dial: %s", host, strings.Join(refusals, "; "))
	}
	return nil, &net.DNSError{Err: "no addresses", Name: host, IsNotFound: true}
}

// ipNetwork is the lookup network for a dial network: tcp4 looks up ip4.
func ipNetwork(network string) string {
	switch network {
	case "tcp4", "udp4":
		return "ip4"
	case "tcp6", "udp6":
		return "ip6"
	}
	return "ip"
}

// control is the last check, run by net.Dialer on the address of the socket
// about to connect. dialer already dials allowed IPs only; this holds even
// if a later change to it doesn't.
func (p *Policy) control(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("dial %s: %w", address, err)
	}
	if why := p.addrRefusal(ap.Addr()); why != "" {
		return refused("address %s %s", ap.Addr(), why)
	}
	return nil
}
