// Package netguard decides where kuzl's requests may go, and builds the one
// http.Client that enforces it, so that the commands can't send a request
// around it.
//
// The rules come from the policy built into the binary (internal/config),
// never from the command line or the environment:
//   - Schemes are http and https only, and a URL can't carry credentials.
//   - Host patterns: example.com matches that host only, and *.example.com
//     matches its subdomains, not example.com itself. A denied host is
//     refused; if any hosts are allowed, every other host is refused too.
//   - Non-public addresses (see Public) and denied address ranges are always
//     refused, checked on the address actually dialed, so a name that
//     resolves to one, now or after a DNS change, can't reach it.
//
// Every redirect hop goes through the same checks as the first request.
package netguard

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"
)

// RefusedError is a request the policy doesn't allow. Its message names the
// host at most, never the path or the query, which can hold tokens.
type RefusedError struct {
	Reason string
}

func (e *RefusedError) Error() string { return e.Reason }

func refused(format string, args ...any) error {
	return &RefusedError{Reason: fmt.Sprintf(format, args...)}
}

// Rules are what a Policy enforces, named as in the policy file.
type Rules struct {
	// AllowHosts, if not empty, are the only hosts requests may go to.
	AllowHosts []HostPattern
	// DenyHosts are refused, even if AllowHosts matches them.
	DenyHosts []HostPattern
	// DenyAddrs are refused on top of the non-public addresses.
	DenyAddrs []netip.Prefix
}

// Policy is the set of hosts and addresses requests may go to.
type Policy struct {
	rules Rules
}

// NewPolicy returns a policy enforcing r. The zero Rules allow every public
// host.
func NewPolicy(r Rules) *Policy {
	return &Policy{rules: r}
}

// HostPattern is a host list entry: one host, or with a leading "*.", its
// subdomains.
type HostPattern struct {
	host string
	sub  bool
}

// ParseHostPattern parses a host list entry. Anything that isn't a host or
// *.host is an error rather than skipped: a typo in the deny list mustn't
// quietly allow the host.
func ParseHostPattern(s string) (HostPattern, error) {
	host, sub := strings.CutPrefix(s, "*.")
	norm, err := normalizeHost(host)
	if err != nil || (sub && isIP(norm)) {
		return HostPattern{}, fmt.Errorf("%q is not a host or *.host", s)
	}
	return HostPattern{host: norm, sub: sub}, nil
}

func (p HostPattern) String() string {
	if p.sub {
		return "*." + p.host
	}
	return p.host
}

func (p HostPattern) match(host string) bool {
	if p.sub {
		return strings.HasSuffix(host, "."+p.host)
	}
	return host == p.host
}

// ParseAddrRange parses an address list entry: an IP, which is a range of
// one, or a CIDR prefix. A prefix with host bits set is an error, as it is
// for Python's ip_network: 10.1.2.3/8 is likelier a typo than 10.0.0.0/8.
// IPv4 ranges are written as IPv4: addresses are matched in their IPv4 form
// whenever they carry one (see canonical), so an IPv4-mapped or NAT64 range
// would match nothing.
func ParseAddrRange(s string) (netip.Prefix, error) {
	var p netip.Prefix
	if ip, err := netip.ParseAddr(s); err == nil {
		// PrefixFrom would drop the zone; ParsePrefix rejects one.
		if ip.Zone() != "" {
			return netip.Prefix{}, fmt.Errorf("%q: an address with a zone is not supported", s)
		}
		p = netip.PrefixFrom(ip, ip.BitLen())
	} else if p, err = netip.ParsePrefix(s); err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is not an IP or CIDR prefix", s)
	}
	switch {
	case p != p.Masked():
		return netip.Prefix{}, fmt.Errorf("%q has host bits set; did you mean %s?", s, p.Masked())
	case p.Addr().Is4In6() || (nat64.Contains(p.Addr()) && p.Bits() >= nat64.Bits()):
		return netip.Prefix{}, fmt.Errorf("%q: write an IPv4 range in IPv4 form", s)
	}
	return p, nil
}

// normalizeHost returns host as the lists match it: lower case, without a
// trailing dot (example.com. resolves as example.com does), and an IP in its
// canonical form, so that one host can't be spelled past a deny entry.
//
// Names must be ASCII. Go's transport converts a Unicode name with IDNA
// before resolving it, which maps such as fullwidth ｇithub.com to
// github.com; refusing them leaves only the spelling that is checked.
func normalizeHost(host string) (string, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Zone() != "" {
			return "", fmt.Errorf("%q: an address with a zone is not supported", host)
		}
		return canonical(ip).String(), nil
	}
	host = strings.TrimRight(strings.ToLower(host), ".")
	if host == "" {
		return "", fmt.Errorf("empty host")
	}
	for _, c := range []byte(host) {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '.' && c != '_' {
			return "", fmt.Errorf("%q: a host name must be ASCII letters, digits, '-', '_' and '.' (use punycode)", host)
		}
	}
	return host, nil
}

func isIP(host string) bool {
	_, err := netip.ParseAddr(host)
	return err == nil
}

// CheckURL returns a *RefusedError if a request to u isn't allowed before
// anything is resolved or dialed. The address check comes again at dial time,
// for names.
func (p *Policy) CheckURL(u *url.URL) error {
	if u.Scheme != "http" && u.Scheme != "https" {
		return refused("protocol %q is not supported: kuzl only fetches http and https", u.Scheme)
	}
	if u.User != nil {
		return refused("credentials in the URL are not supported")
	}
	if u.Hostname() == "" {
		return refused("the URL has no host")
	}
	host, err := normalizeHost(u.Hostname())
	if err != nil {
		return &RefusedError{Reason: err.Error()}
	}
	return p.checkHost(host)
}

func (p *Policy) checkHost(host string) error {
	if matchAny(p.rules.DenyHosts, host) {
		return refused("host %s is in deny_hosts", host)
	}
	if len(p.rules.AllowHosts) > 0 && !matchAny(p.rules.AllowHosts, host) {
		return refused("host %s is not in allow_hosts", host)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if why := p.addrRefusal(ip); why != "" {
			return refused("address %s %s", ip, why)
		}
	}
	return nil
}

// addrRefusal says why ip may not be dialed, or returns "" if it may.
func (p *Policy) addrRefusal(ip netip.Addr) string {
	if !Public(ip) {
		return "is not public"
	}
	ip = canonical(ip)
	for _, r := range p.rules.DenyAddrs {
		if r.Contains(ip) {
			return "is in deny_addrs"
		}
	}
	return ""
}

func matchAny(pats []HostPattern, host string) bool {
	for _, pat := range pats {
		if pat.match(host) {
			return true
		}
	}
	return false
}
