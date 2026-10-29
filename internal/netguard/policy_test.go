package netguard

import (
	"errors"
	"net/url"
	"strings"
	"testing"
)

func mustPolicy(t *testing.T, allow, deny []string, denyAddrs ...string) *Policy {
	t.Helper()
	var r Rules
	for _, s := range allow {
		r.AllowHosts = append(r.AllowHosts, mustHost(t, s))
	}
	for _, s := range deny {
		r.DenyHosts = append(r.DenyHosts, mustHost(t, s))
	}
	for _, s := range denyAddrs {
		p, err := ParseAddrRange(s)
		if err != nil {
			t.Fatal(err)
		}
		r.DenyAddrs = append(r.DenyAddrs, p)
	}
	return NewPolicy(r)
}

func mustHost(t *testing.T, s string) HostPattern {
	t.Helper()
	p, err := ParseHostPattern(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// wantRefused checks that err is a *RefusedError containing substr, or nil
// if substr is empty.
func wantRefused(t *testing.T, err error, substr string) {
	t.Helper()
	if substr == "" {
		if err != nil {
			t.Errorf("err = %v, want nil", err)
		}
		return
	}
	re, ok := errors.AsType[*RefusedError](err)
	if !ok || !strings.Contains(re.Reason, substr) {
		t.Errorf("err = %#v, want a *RefusedError containing %q", err, substr)
	}
}

func TestParseHostPattern(t *testing.T) {
	for in, want := range map[string]string{
		"example.com":      "example.com",
		"GitHub.com.":      "github.com",
		"*.Example.ORG":    "*.example.org",
		"1.2.3.4":          "1.2.3.4",
		"2001:4860::1":     "2001:4860::1",
		"::ffff:1.2.3.4":   "1.2.3.4",
		"64:ff9b::102:304": "1.2.3.4",
	} {
		p, err := ParseHostPattern(in)
		if err != nil || p.String() != want {
			t.Errorf("ParseHostPattern(%q) = %v, %v; want %s", in, p, err, want)
		}
	}
	// A bad entry is an error, never skipped: skipping it would allow what it
	// meant to deny.
	for _, in := range []string{
		"", "*", "*.", "*example.com", "ex*.com", "example.*", "https://example.com",
		"example.com:443", "example.com/path", "ｇithub.com", "*.1.2.3.4", "fe80::1%eth0",
	} {
		if p, err := ParseHostPattern(in); err == nil {
			t.Errorf("ParseHostPattern(%q) = %v, want an error", in, p)
		}
	}
}

func TestParseAddrRange(t *testing.T) {
	for in, want := range map[string]string{
		"8.8.4.4":        "8.8.4.4/32",
		"10.0.0.0/8":     "10.0.0.0/8",
		"2001:4860::1":   "2001:4860::1/128",
		"2606:4700::/32": "2606:4700::/32",
		"64:ff9b::/95":   "64:ff9b::/95",
		"0.0.0.0/0":      "0.0.0.0/0",
	} {
		p, err := ParseAddrRange(in)
		if err != nil || p.String() != want {
			t.Errorf("ParseAddrRange(%q) = %v, %v; want %s", in, p, err, want)
		}
	}
	for in, want := range map[string]string{
		"":                  "not an IP or CIDR",
		"example.com":       "not an IP or CIDR",
		"10.0.0.0/33":       "not an IP or CIDR",
		"10.1.2.3/8":        "did you mean 10.0.0.0/8?",
		"fe80::1%eth0":      "zone",
		"::ffff:1.2.3.4":    "IPv4 form",
		"::ffff:0.0.0.0/96": "IPv4 form",
		"64:ff9b::102:304":  "IPv4 form",
		"64:ff9b::/96":      "IPv4 form",
	} {
		if _, err := ParseAddrRange(in); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("ParseAddrRange(%q) = %v, want an error containing %q", in, err, want)
		}
	}
}

func TestCheckURL(t *testing.T) {
	deny := mustPolicy(t, nil, []string{"github.com", "raw.githubusercontent.com", "*.evil.test", "8.8.4.4"},
		"9.9.9.0/24", "2620:fe::/48")
	allow := mustPolicy(t, []string{"api.example.com", "*.example.org", "8.8.8.8"}, []string{"bad.example.org"})

	tests := []struct {
		policy *Policy
		url    string
		want   string // "" for allowed, or what the refusal says
	}{
		{deny, "https://example.com/x?token=1", ""},
		{deny, "http://example.com:8080/", ""},
		{deny, "https://api.github.com/repos", ""}, // github.com is exact
		{deny, "https://8.8.8.8/", ""},
		{deny, "https://[2606:4700::1111]/", ""},
		{deny, "https://github.com/x", "host github.com is in deny_hosts"},
		// Other spellings of a denied host.
		{deny, "https://GitHub.COM/x", "deny_hosts"},
		{deny, "https://github.com./x", "deny_hosts"},
		{deny, "https://github.com../x", "deny_hosts"},
		{deny, "https://github.com:443/x", "deny_hosts"},
		{deny, "https://ｇithub.com/x", "must be ASCII"},
		{deny, "https://gith%C3%BCb.com/x", "must be ASCII"},
		{deny, "https://a.evil.test/", "deny_hosts"},
		{deny, "https://a.b.evil.test/", "deny_hosts"},
		{deny, "https://evil.test/", ""}, // *.evil.test is subdomains only
		{deny, "https://notevil.test/", ""},
		{deny, "https://8.8.4.4/", "deny_hosts"},
		{deny, "https://[::ffff:8.8.4.4]/", "deny_hosts"},
		{deny, "https://[64:ff9b::808:404]/", "deny_hosts"}, // NAT64 spelling
		// deny_addrs, in every spelling of the address.
		{deny, "https://9.9.9.9/", "address 9.9.9.9 is in deny_addrs"},
		{deny, "https://[::ffff:9.9.9.9]/", "address 9.9.9.9 is in deny_addrs"},
		{deny, "https://[64:ff9b::909:909]/", "address 9.9.9.9 is in deny_addrs"},
		{deny, "https://[2620:fe::fe]/", "address 2620:fe::fe is in deny_addrs"},
		{deny, "https://9.9.10.1/", ""},
		// Never public, whatever the lists say.
		{deny, "http://127.0.0.1/", "address 127.0.0.1 is not public"},
		{deny, "http://169.254.169.254/latest/meta-data/", "not public"},
		{deny, "http://[::1]:8080/", "not public"},
		{deny, "http://[::ffff:127.0.0.1]/", "address 127.0.0.1 is not public"},
		{deny, "http://[fe80::1%25eth0]/", "zone"},
		// Schemes and URL shapes.
		{deny, "file:///etc/passwd", `protocol "file" is not supported`},
		{deny, "ftp://example.com/", `protocol "ftp"`},
		{deny, "gopher://example.com/", `protocol "gopher"`},
		{deny, "//example.com/", `protocol ""`},
		{deny, "HTTPS://example.com/", ""},
		{deny, "http:example.com", "no host"},
		{deny, "http:///x", "no host"},
		{deny, "https://user:pass@example.com/", "credentials"},
		{deny, "https://user@example.com/", "credentials"},

		{allow, "https://api.example.com/v1", ""},
		{allow, "https://a.example.org/", ""},
		{allow, "https://8.8.8.8/", ""},
		{allow, "https://example.com/", "host example.com is not in allow_hosts"},
		{allow, "https://example.org/", "not in"},
		{allow, "https://x.api.example.com/", "not in"},
		{allow, "https://bad.example.org/", "deny_hosts"}, // deny wins
		{allow, "https://1.1.1.1/", "not in"},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			u, err := url.Parse(tt.url)
			if err != nil {
				t.Fatal(err)
			}
			wantRefused(t, tt.policy.CheckURL(u), tt.want)
		})
	}
}

// A refusal names the host but never the path or the query.
func TestRefusalsLeaveOutThePath(t *testing.T) {
	p := mustPolicy(t, []string{"example.com"}, []string{"github.com"})
	for _, raw := range []string{
		"https://github.com/SEKRET?token=SEKRET",
		"https://other.example/SEKRET?token=SEKRET",
		"ftp://example.com/SEKRET?token=SEKRET",
		"https://u:SEKRET@example.com/",
	} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := p.CheckURL(u); err == nil || strings.Contains(err.Error(), "SEKRET") {
			t.Errorf("CheckURL(%s) = %v, want a refusal without SEKRET", raw, err)
		}
	}
}
