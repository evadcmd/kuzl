// Package config is kuzl's policy file: a YAML document built into the
// binary, so that what an agent runs can't change it, and kept out of the
// repo, so that changing it takes a rebuild rather than a commit. The
// Makefile builds it in:
//
//	make build POLICY=/path/to/policy.yaml
//
// which sets builtin with
//
//	-ldflags "-X github.com/evadcmd/kuzl/internal/config.builtin=$(base64 < policy.yaml | tr -d '\n')"
//
// The file is decoded with strictyaml: an unknown key is an error, and every
// error is reported with its location. policy.example.yaml lists the keys.
package config

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"regexp"

	"github.com/evadcmd/kuzl/internal/netguard"
	"github.com/evadcmd/kuzl/internal/strictyaml"
	"go.yaml.in/yaml/v3"
)

// builtin is the policy file, base64-encoded, as the build sets it. Empty is
// no file, which allows every public host.
var builtin string

// file is the policy file. A field is required unless it is Optional.
type file struct {
	// AllowHosts, if set, are the only hosts requests may go to; left out,
	// every public host is.
	AllowHosts strictyaml.Optional[allowList] `yaml:"allow_hosts"`
	// DenyHosts are refused, even if AllowHosts matches them.
	DenyHosts strictyaml.Optional[[]hostPattern] `yaml:"deny_hosts"`
	// DenyAddrs are IPs and CIDR prefixes refused on top of the non-public
	// addresses, checked on the address dialed.
	DenyAddrs strictyaml.Optional[[]addrRange] `yaml:"deny_addrs"`
}

type hostPattern struct{ netguard.HostPattern }

func (p *hostPattern) UnmarshalYAML(n *yaml.Node) error {
	s, err := str(n)
	if err != nil {
		return err
	}
	p.HostPattern, err = netguard.ParseHostPattern(s)
	return err
}

type addrRange struct{ netip.Prefix }

func (r *addrRange) UnmarshalYAML(n *yaml.Node) error {
	s, err := str(n)
	if err != nil {
		return err
	}
	r.Prefix, err = netguard.ParseAddrRange(s)
	return err
}

// str is n as a string, which it must be: 1.5 or true in a host list is a
// mistake, not a host.
func str(n *yaml.Node) (string, error) {
	if n.Kind != yaml.ScalarNode || n.Tag != "!!str" {
		return "", errors.New("should be a string")
	}
	return n.Value, nil
}

// allowList is allow_hosts, which can't be empty: allow_hosts: [] would
// read as allowing nothing, but an empty list is no restriction.
type allowList []hostPattern

func (l allowList) Validate() error {
	if len(l) == 0 {
		return errors.New("should not be empty; leave allow_hosts out to allow every public host")
	}
	return nil
}

// unquotedStar finds a list item starting with *, which YAML reads as an
// alias, so that the syntax error it causes can say so.
var unquotedStar = regexp.MustCompile(`(?m)^\s*-\s*\*`)

// Parse decodes a policy file. A syntax error is yaml's; a value that
// doesn't validate is a *strictyaml.ValidationError listing them all.
func Parse(data []byte) (netguard.Rules, error) {
	var f file
	if err := strictyaml.Unmarshal(data, &f); err != nil {
		if _, ok := errors.AsType[*strictyaml.ValidationError](err); !ok && unquotedStar.Match(data) {
			err = fmt.Errorf(`%w (a value starting with * must be quoted, as in "*.example.com")`, err)
		}
		return netguard.Rules{}, err
	}
	var r netguard.Rules
	for _, p := range f.AllowHosts.Or(nil) {
		r.AllowHosts = append(r.AllowHosts, p.HostPattern)
	}
	for _, p := range f.DenyHosts.Or(nil) {
		r.DenyHosts = append(r.DenyHosts, p.HostPattern)
	}
	for _, a := range f.DenyAddrs.Or(nil) {
		r.DenyAddrs = append(r.DenyAddrs, a.Prefix)
	}
	return r, nil
}

// Builtin returns the rules of the policy file built into the binary.
func Builtin() (netguard.Rules, error) {
	return decode(builtin)
}

func decode(encoded string) (netguard.Rules, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return netguard.Rules{}, fmt.Errorf("the built-in policy is not base64 (build with make build POLICY=...): %w", err)
	}
	r, err := Parse(data)
	if err != nil {
		return netguard.Rules{}, fmt.Errorf("the built-in policy: %w", err)
	}
	return r, nil
}

// Format writes r as a policy file, in normalized form: Parse(Format(r))
// returns r.
func Format(r netguard.Rules) []byte {
	var out struct {
		AllowHosts []string `yaml:"allow_hosts,omitempty"`
		DenyHosts  []string `yaml:"deny_hosts"`
		DenyAddrs  []string `yaml:"deny_addrs"`
	}
	out.DenyHosts, out.DenyAddrs = []string{}, []string{}
	for _, p := range r.AllowHosts {
		out.AllowHosts = append(out.AllowHosts, p.String())
	}
	for _, p := range r.DenyHosts {
		out.DenyHosts = append(out.DenyHosts, p.String())
	}
	for _, a := range r.DenyAddrs {
		if a.IsSingleIP() {
			out.DenyAddrs = append(out.DenyAddrs, a.Addr().String())
		} else {
			out.DenyAddrs = append(out.DenyAddrs, a.String())
		}
	}
	var b bytes.Buffer
	if len(r.AllowHosts) == 0 {
		b.WriteString("# allow_hosts is left out: every public host is allowed.\n")
	}
	e := yaml.NewEncoder(&b)
	e.SetIndent(2)
	if err := errors.Join(e.Encode(out), e.Close()); err != nil {
		panic(err) // a struct of string lists always encodes
	}
	return b.Bytes()
}
