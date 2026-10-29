// Package netguard decides where kuzl's requests may go, and builds the one
// http.Client that enforces it, so that the commands can't send a request
// around it.
//
// The policy comes from the environment, never from the command line:
//   - Schemes are http and https only, and a URL can't carry credentials.
//   - KUZL_DENY_HOSTS and KUZL_ALLOW_HOSTS are comma-separated host patterns.
//     example.com matches that host only, and *.example.com matches its
//     subdomains, not example.com itself. Deny wins. An empty allow list
//     allows every public host.
//   - Non-public addresses are always refused (see Public), checked on the
//     address actually dialed, so a name that resolves to one, now or after
//     a DNS change, can't reach it.
//
// Every redirect hop goes through the same checks as the first request.
package netguard

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"
)

// The variables the host lists are read from.
const (
	EnvAllowHosts = "KUZL_ALLOW_HOSTS"
	EnvDenyHosts  = "KUZL_DENY_HOSTS"
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

// Policy is the set of hosts requests may go to.
type Policy struct {
	allow, deny []pattern
}

// pattern is a host list entry: host itself, or with sub, its subdomains.
type pattern struct {
	host string
	sub  bool
}

func (p pattern) match(host string) bool {
	if p.sub {
		return strings.HasSuffix(host, "."+p.host)
	}
	return host == p.host
}

// FromEnv reads the policy from KUZL_ALLOW_HOSTS and KUZL_DENY_HOSTS with
// getenv.
func FromEnv(getenv func(string) string) (*Policy, error) {
	return NewPolicy(splitList(getenv(EnvAllowHosts)), splitList(getenv(EnvDenyHosts)))
}

func splitList(s string) []string {
	var list []string
	for item := range strings.SplitSeq(s, ",") {
		if item = strings.TrimSpace(item); item != "" {
			list = append(list, item)
		}
	}
	return list
}

// NewPolicy returns a policy allowing the hosts matched by allow, or every
// public host if allow is empty, except those matched by deny. An entry that
// isn't a host or *.host is an error rather than skipped: a typo in the deny
// list mustn't quietly allow the host.
func NewPolicy(allow, deny []string) (*Policy, error) {
	p := &Policy{}
	for _, l := range []struct {
		env     string
		entries []string
		dst     *[]pattern
	}{{EnvAllowHosts, allow, &p.allow}, {EnvDenyHosts, deny, &p.deny}} {
		for _, entry := range l.entries {
			pat, err := parsePattern(entry)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", l.env, err)
			}
			*l.dst = append(*l.dst, pat)
		}
	}
	return p, nil
}

func parsePattern(entry string) (pattern, error) {
	host, sub := strings.CutPrefix(entry, "*.")
	norm, err := normalizeHost(host)
	if err != nil || (sub && isIP(norm)) {
		return pattern{}, fmt.Errorf("%q is not a host or *.host", entry)
	}
	return pattern{host: norm, sub: sub}, nil
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
		return ip.Unmap().String(), nil
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
	for _, pat := range p.deny {
		if pat.match(host) {
			return refused("host %s is denied by %s", host, EnvDenyHosts)
		}
	}
	if len(p.allow) > 0 && !matchAny(p.allow, host) {
		return refused("host %s is not in %s", host, EnvAllowHosts)
	}
	if ip, err := netip.ParseAddr(host); err == nil && !Public(ip) {
		return refused("address %s is not public", ip)
	}
	return nil
}

func matchAny(pats []pattern, host string) bool {
	for _, pat := range pats {
		if pat.match(host) {
			return true
		}
	}
	return false
}
