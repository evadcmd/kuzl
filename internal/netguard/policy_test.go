package netguard

import (
	"errors"
	"net/url"
	"strings"
	"testing"
)

func mustPolicy(t *testing.T, allow, deny []string) *Policy {
	t.Helper()
	p, err := NewPolicy(allow, deny)
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

func TestFromEnv(t *testing.T) {
	env := map[string]string{
		EnvAllowHosts: " example.com, *.example.org ,,",
		EnvDenyHosts:  "GitHub.com.",
	}
	p, err := FromEnv(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	want := &Policy{
		allow: []pattern{{host: "example.com"}, {host: "example.org", sub: true}},
		deny:  []pattern{{host: "github.com"}},
	}
	if !equalPatterns(p.allow, want.allow) || !equalPatterns(p.deny, want.deny) {
		t.Errorf("FromEnv = %+v, want %+v", p, want)
	}

	p, err = FromEnv(func(string) string { return "" })
	if err != nil || len(p.allow)+len(p.deny) != 0 {
		t.Errorf("FromEnv(unset) = %+v, %v; want an empty policy", p, err)
	}
}

func equalPatterns(a, b []pattern) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// A bad entry fails the whole policy: skipping it would allow what it meant
// to deny.
func TestNewPolicyRejectsBadEntries(t *testing.T) {
	for _, entry := range []string{
		"*", "*.", "*example.com", "ex*.com", "example.*", "https://example.com",
		"example.com:443", "example.com/path", "ｇithub.com", "*.1.2.3.4", "fe80::1%eth0",
	} {
		_, err := NewPolicy(nil, []string{entry})
		if err == nil || !strings.HasPrefix(err.Error(), EnvDenyHosts+": ") {
			t.Errorf("NewPolicy(deny %q) = %v, want an error naming %s", entry, err, EnvDenyHosts)
		}
	}
	if _, err := NewPolicy([]string{"*.x"}, []string{"1.2.3.4", "2001:4860::1", "*.example.com"}); err != nil {
		t.Errorf("NewPolicy with valid entries = %v, want ok", err)
	}
}

func TestCheckURL(t *testing.T) {
	deny := mustPolicy(t, nil, []string{"github.com", "raw.githubusercontent.com", "*.evil.test", "8.8.4.4"})
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
		{deny, "https://github.com/x", "host github.com is denied by KUZL_DENY_HOSTS"},
		// Other spellings of a denied host.
		{deny, "https://GitHub.COM/x", "denied"},
		{deny, "https://github.com./x", "denied"},
		{deny, "https://github.com../x", "denied"},
		{deny, "https://github.com:443/x", "denied"},
		{deny, "https://ｇithub.com/x", "must be ASCII"},
		{deny, "https://gith%C3%BCb.com/x", "must be ASCII"},
		{deny, "https://a.evil.test/", "denied"},
		{deny, "https://a.b.evil.test/", "denied"},
		{deny, "https://evil.test/", ""}, // *.evil.test is subdomains only
		{deny, "https://notevil.test/", ""},
		{deny, "https://8.8.4.4/", "denied"},
		{deny, "https://[::ffff:8.8.4.4]/", "denied"},
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
		{allow, "https://example.com/", "host example.com is not in KUZL_ALLOW_HOSTS"},
		{allow, "https://example.org/", "not in"},
		{allow, "https://x.api.example.com/", "not in"},
		{allow, "https://bad.example.org/", "denied"}, // deny wins
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
