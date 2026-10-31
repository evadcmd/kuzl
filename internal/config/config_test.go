package config

import (
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestParse(t *testing.T) {
	r, err := Parse([]byte(`
allow_hosts:
  - API.example.com.
  - "*.example.org"
deny_hosts:
  - bad.example.org
deny_addrs:
  - 8.8.4.4
  - 9.9.9.0/24
  - 2620:fe::/48
max_stdout_bytes: 30000
`))
	if err != nil {
		t.Fatal(err)
	}
	want := `allow_hosts:
  - api.example.com
  - '*.example.org'
deny_hosts:
  - bad.example.org
deny_addrs:
  - 8.8.4.4
  - 9.9.9.0/24
  - 2620:fe::/48
max_stdout_bytes: 30000
`
	if got := string(Format(r)); got != want {
		t.Errorf("Format(Parse) =\n%s\nwant\n%s", got, want)
	}
	// Format's output parses back to the same rules.
	again, err := Parse(Format(r))
	if err != nil || !reflect.DeepEqual(again, r) {
		t.Errorf("Parse(Format(r)) = %+v, %v; want %+v", again, err, r)
	}
}

// Every key is optional: an empty file, or one with only comments, allows no
// host, and caps stdout at the default.
func TestParseEmpty(t *testing.T) {
	for _, doc := range []string{"", "# nothing\n", "{}", "---\n{}\n", "deny_hosts:\ndeny_addrs: null\nmax_stdout_bytes: ~\n"} {
		r, err := Parse([]byte(doc))
		if err != nil || len(r.AllowHosts)+len(r.DenyHosts)+len(r.DenyAddrs) != 0 || r.MaxStdoutBytes != DefaultMaxStdoutBytes {
			t.Errorf("Parse(%q) = %+v, %v; want empty rules and the default cap", doc, r, err)
		}
	}
	want := "# allow_hosts is empty: no host is allowed.\nallow_hosts: []\ndeny_hosts: []\ndeny_addrs: []\nmax_stdout_bytes: 48000\n"
	r, _ := Parse(nil)
	if got := string(Format(r)); got != want {
		t.Errorf("Format(empty) = %q, want %q", got, want)
	}
}

// Unknown keys and values of the wrong type are reported together, each with
// its line. A key given twice is reported first, on its own.
func TestParseTypeErrors(t *testing.T) {
	for doc, wants := range map[string][]string{
		"deny_host:\n  - github.com\ndeny_addrs: 1.0.0.1\n": {
			"line 1: field deny_host not found",
			"line 3: cannot unmarshal !!str `1.0.0.1`",
		},
		"deny_host: []\nallow_hosts: [a.example]\nallow_hosts: [b.example]\n": {
			`line 3: mapping key "allow_hosts" already defined at line 2`,
		},
	} {
		_, err := Parse([]byte(doc))
		if _, ok := errors.AsType[*yaml.TypeError](err); !ok {
			t.Errorf("Parse(%q) = %v, want a *yaml.TypeError", doc, err)
			continue
		}
		for _, want := range wants {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("Parse(%q) = %v, want it to contain %q", doc, err, want)
			}
		}
	}
}

// An entry that isn't valid fails the whole file, with its line: skipping
// it would allow what it meant to deny.
func TestParseEntryErrors(t *testing.T) {
	for doc, want := range map[string]string{
		"deny_hosts:\n  - \"*example.com\"\n":       `line 2: "*example.com" is not a host, *.host or *`,
		"deny_hosts: [ok.example, 1.5]\n":           "line 1: an entry should be a string, not !!float",
		"deny_hosts:\n  - [a]\n":                    "line 2: an entry should be a string, not !!seq",
		"allow_hosts:\n  - true\n":                  "line 2: an entry should be a string, not !!bool",
		"deny_addrs:\n  - 10.1.2.3/8\n":             `line 2: "10.1.2.3/8" has host bits set; did you mean 10.0.0.0/8?`,
		"deny_addrs:\n  - fe80::1%eth0\n":           `line 2: "fe80::1%eth0": an address with a zone is not supported`,
		"deny_addrs:\n  - 8.8.8.8\n  - example.com": `line 3: "example.com" is not an IP or CIDR prefix`,
		// yaml would drop a null item rather than decode it.
		"deny_hosts: [a.example, ~]\n":          "line 1: an entry should be a string, not !!null",
		"deny_addrs:\n  - 8.8.8.8\n  -\n":       "line 3: an entry should be a string, not !!null",
		"allow_hosts: [null]\n":                 "line 1: an entry should be a string, not !!null",
		"deny_hosts: &n ~\nallow_hosts: [*n]\n": "line 2: an entry should be a string, not !!null",
	} {
		_, err := Parse([]byte(doc))
		if _, ok := errors.AsType[*EntryError](err); !ok || err.Error() != want {
			t.Errorf("Parse(%q) = %v, want the *EntryError %q", doc, err, want)
		}
	}
}

// max_stdout_bytes is a whole number of bytes, from 1 to 100 MiB; anything
// else fails the file, with its line.
func TestParseMaxStdoutBytes(t *testing.T) {
	for doc, want := range map[string]int{
		"max_stdout_bytes: 1\n":         1,
		"max_stdout_bytes: 100000\n":    100000,
		"max_stdout_bytes: 104857600\n": 104857600,
	} {
		if p, err := Parse([]byte(doc)); err != nil || p.MaxStdoutBytes != want {
			t.Errorf("Parse(%q) = %+v, %v; want max_stdout_bytes %d", doc, p, err, want)
		}
	}
	for doc, want := range map[string]string{
		"max_stdout_bytes: 0\n":                    "line 1: max_stdout_bytes 0: want 1 to 104857600",
		"deny_hosts: []\nmax_stdout_bytes: -1\n":   "line 2: max_stdout_bytes -1: want 1 to 104857600",
		"max_stdout_bytes: 104857601\n":            "line 1: max_stdout_bytes 104857601: want 1 to 104857600",
		"max_stdout_bytes: 99999999999999999999\n": "line 1: max_stdout_bytes 99999999999999999999: want 1 to 104857600",
		"max_stdout_bytes: 9223372036854775808\n":  "line 1: max_stdout_bytes 9223372036854775808: want 1 to 104857600",
		"max_stdout_bytes: !!float 5\n":            "line 1: max_stdout_bytes should be a number of bytes, not !!float",
		"max_stdout_bytes: \"48000\"\n":            "line 1: max_stdout_bytes should be a number of bytes, not !!str",
		"max_stdout_bytes: 48k\n":                  "line 1: max_stdout_bytes should be a number of bytes, not !!str",
		"max_stdout_bytes: 1.5\n":                  "line 1: max_stdout_bytes should be a number of bytes, not !!float",
		"max_stdout_bytes: [1]\n":                  "line 1: max_stdout_bytes should be a number of bytes, not !!seq",
	} {
		_, err := Parse([]byte(doc))
		if _, ok := errors.AsType[*EntryError](err); !ok || err.Error() != want {
			t.Errorf("Parse(%q) = %v, want the *EntryError %q", doc, err, want)
		}
	}
}

// Empty or null, allow_hosts allows no host, as left out; "*" is every public
// host.
func TestParseAllowList(t *testing.T) {
	for _, doc := range []string{
		"allow_hosts: []\n",
		"allow_hosts:\n#  - api.example.com\n",
		"allow_hosts: ~\n",
		"deny_hosts: [a.example]\nallow_hosts: null\n",
	} {
		r, err := Parse([]byte(doc))
		if err != nil || len(r.AllowHosts) != 0 {
			t.Errorf("Parse(%q) = %+v, %v; want an empty allow_hosts", doc, r, err)
		}
	}
	r, err := Parse([]byte("allow_hosts: [\"*\"]\n"))
	if err != nil || len(r.AllowHosts) != 1 || r.AllowHosts[0].String() != "*" {
		t.Fatalf("Parse(*) = %+v, %v; want allow_hosts *", r, err)
	}
	want := "allow_hosts:\n  - '*'\ndeny_hosts: []\ndeny_addrs: []\nmax_stdout_bytes: 48000\n"
	if got := string(Format(r)); got != want {
		t.Errorf("Format(*) = %q, want %q", got, want)
	}
	if again, err := Parse(Format(r)); err != nil || !reflect.DeepEqual(again, r) {
		t.Errorf("Parse(Format(r)) = %+v, %v; want %+v", again, err, r)
	}
}

// yaml decodes the first document only, so a second one would be dropped
// with the rules in it.
func TestParseRefusesSecondDocument(t *testing.T) {
	_, err := Parse([]byte("deny_hosts: [a.example]\n---\ndeny_hosts: [b.example]\n"))
	if want := "line 2: the policy should be one YAML document, without ---"; err == nil || err.Error() != want {
		t.Errorf("err = %v, want %q", err, want)
	}
	if _, err := Parse([]byte("deny_hosts: [a.example]\n---\n- [b\n")); err == nil {
		t.Error("a second document with a syntax error parsed")
	}
}

// YAML reads an unquoted * as an alias; the error says to quote it.
func TestParseUnquotedStar(t *testing.T) {
	for _, doc := range []string{
		"deny_hosts:\n  - *.evil.example\n",
		"deny_hosts: [*.evil.example]\n",
		"deny_hosts: [a.example, *.evil.example]\n",
		"deny_hosts: *.evil.example\n",
		"allow_hosts: [*]\n",
	} {
		if _, err := Parse([]byte(doc)); err == nil || !strings.Contains(err.Error(), "must be quoted") {
			t.Errorf("Parse(%q) = %v, want a hint to quote *", doc, err)
		}
	}
	for _, doc := range []string{
		"deny_hosts: [a\n",
		// A real alias, and an error that isn't a syntax error.
		"deny_hosts:\n  - &h a.example\nallow_hosts:\n  - *h\nfoo: 1\n",
		// A * in a comment, and an unrelated syntax error.
		"# e.g.: *.example.com\ndeny_hosts: [a\n",
		// An anchor name that isn't valid, rather than an alias.
		"deny_hosts: [&.x]\n",
	} {
		if _, err := Parse([]byte(doc)); err == nil || strings.Contains(err.Error(), "must be quoted") {
			t.Errorf("Parse(%q) = %v, want an error without the hint", doc, err)
		}
	}
}

func TestDecode(t *testing.T) {
	if r, err := decode(""); err != nil || len(r.AllowHosts)+len(r.DenyHosts)+len(r.DenyAddrs) != 0 {
		t.Errorf("no built-in policy: %+v, %v; want empty rules", r, err)
	}
	if r, err := decode(base64.StdEncoding.EncodeToString([]byte("deny_addrs:\n  - 1.0.0.0/24\n"))); err != nil || len(r.DenyAddrs) != 1 || r.DenyAddrs[0].String() != "1.0.0.0/24" {
		t.Errorf("decode() = %+v, %v; want deny_addrs 1.0.0.0/24", r, err)
	}
	if r, err := decode(base64.StdEncoding.EncodeToString([]byte("max_stdout_bytes: 30000\n"))); err != nil || r.MaxStdoutBytes != 30000 {
		t.Errorf("decode() = %+v, %v; want max_stdout_bytes 30000", r, err)
	}
	for in, want := range map[string]string{
		"deny_addrs: [1.0.0.0/24]":                                 "not base64",
		base64.StdEncoding.EncodeToString([]byte("deny_addr: []")): "the built-in policy: yaml: unmarshal errors:\n  line 1: field deny_addr not found",
	} {
		if _, err := decode(in); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("decode(%q) = %v, want an error containing %q", in, err, want)
		}
	}
}
