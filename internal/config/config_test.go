package config

import (
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/evadcmd/kuzl/internal/strictyaml"
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

// Every key is Optional: an empty file, or one with only comments, allows
// every public host.
func TestParseEmpty(t *testing.T) {
	for _, doc := range []string{"", "# nothing\n", "{}", "deny_hosts:\ndeny_addrs: null\n"} {
		r, err := Parse([]byte(doc))
		if err != nil || len(r.AllowHosts)+len(r.DenyHosts)+len(r.DenyAddrs) != 0 {
			t.Errorf("Parse(%q) = %+v, %v; want empty rules", doc, r, err)
		}
	}
	want := "# allow_hosts is left out: every public host is allowed.\ndeny_hosts: []\ndeny_addrs: []\n"
	r, _ := Parse(nil)
	if got := string(Format(r)); got != want {
		t.Errorf("Format(empty) = %q, want %q", got, want)
	}
}

// A file that doesn't validate fails as a whole, with every error and where
// it is: skipping a bad entry would allow what it meant to deny.
func TestParseErrors(t *testing.T) {
	_, err := Parse([]byte(`deny_host:
  - github.com
deny_hosts:
  - "*example.com"
  - 1.5
  - [a]
deny_addrs:
  - 10.1.2.3/8
  - fe80::1%eth0
  - example.com
allow_hosts: []
`))
	ve, ok := errors.AsType[*strictyaml.ValidationError](err)
	if !ok {
		t.Fatalf("err = %v, want a *strictyaml.ValidationError", err)
	}
	want := []strictyaml.FieldError{
		{Loc: "deny_host", Line: 1, Msg: "unknown field"},
		{Loc: "deny_hosts.0", Line: 4, Msg: `"*example.com" is not a host or *.host`},
		{Loc: "deny_hosts.1", Line: 5, Msg: "should be a string"},
		{Loc: "deny_hosts.2", Line: 6, Msg: "should be a string"},
		{Loc: "deny_addrs.0", Line: 8, Msg: `"10.1.2.3/8" has host bits set; did you mean 10.0.0.0/8?`},
		{Loc: "deny_addrs.1", Line: 9, Msg: `"fe80::1%eth0": an address with a zone is not supported`},
		{Loc: "deny_addrs.2", Line: 10, Msg: `"example.com" is not an IP or CIDR prefix`},
		{Loc: "allow_hosts", Line: 11, Msg: "should not be empty; leave allow_hosts out to allow every public host"},
	}
	if !reflect.DeepEqual(ve.Errors, want) {
		t.Errorf("errors =\n%v\nwant\n%v", ve.Errors, want)
	}
}

// YAML reads an unquoted * as an alias; the error says to quote it.
func TestParseUnquotedStar(t *testing.T) {
	_, err := Parse([]byte("deny_hosts:\n  - *.evil.example\n"))
	if err == nil || !strings.Contains(err.Error(), "must be quoted") {
		t.Errorf("err = %v, want a hint to quote *", err)
	}
	_, err = Parse([]byte("deny_hosts: [a\n"))
	if err == nil || strings.Contains(err.Error(), "must be quoted") {
		t.Errorf("err = %v, want a syntax error without the hint", err)
	}
}

func TestBuiltin(t *testing.T) {
	defer func(old string) { builtin = old }(builtin)

	builtin = ""
	if r, err := Builtin(); err != nil || len(r.AllowHosts)+len(r.DenyHosts)+len(r.DenyAddrs) != 0 {
		t.Errorf("no built-in policy: %+v, %v; want empty rules", r, err)
	}
	builtin = base64.StdEncoding.EncodeToString([]byte("deny_addrs:\n  - 1.0.0.0/24\n"))
	if r, err := Builtin(); err != nil || len(r.DenyAddrs) != 1 || r.DenyAddrs[0].String() != "1.0.0.0/24" {
		t.Errorf("Builtin() = %+v, %v; want deny_addrs 1.0.0.0/24", r, err)
	}
	for in, want := range map[string]string{
		"deny_addrs: [1.0.0.0/24]":                                 "not base64",
		base64.StdEncoding.EncodeToString([]byte("deny_addr: []")): "the built-in policy: 1 validation error",
	} {
		builtin = in
		if _, err := Builtin(); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Builtin(%q) = %v, want an error containing %q", in, err, want)
		}
	}
}
