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
// The file is decoded strictly: an unknown key is an error rather than
// ignored, so a typo such as deny_host can't quietly drop a list.
// policy.example.yaml lists the keys.
package config

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strings"

	"github.com/evadcmd/kuzl/internal/netguard"
	"go.yaml.in/yaml/v3"
)

// builtin is the policy file, base64-encoded, as the build sets it. Empty is
// no file, which allows every public host.
var builtin string

// file is the policy file. A pointer field is an optional key: nil is the
// key left out, or set to null. Parse tells the two apart for AllowHosts.
type file struct {
	// AllowHosts, if set, are the only hosts requests may go to; left out,
	// every public host is. Set, it can't be empty or null.
	AllowHosts *list[hostPattern] `yaml:"allow_hosts"`
	// DenyHosts are refused, even if AllowHosts matches them.
	DenyHosts *list[hostPattern] `yaml:"deny_hosts"`
	// DenyAddrs are IPs and CIDR prefixes refused on top of the non-public
	// addresses, checked on the address dialed.
	DenyAddrs *list[addrRange] `yaml:"deny_addrs"`
}

// list is a list of entries. yaml drops a null item from a slice without
// calling its UnmarshalYAML, so list checks for one itself: like 1.5, a null
// is a mistake, not an entry to skip.
type list[T any] []T

func (l *list[T]) UnmarshalYAML(n *yaml.Node) error {
	for _, item := range n.Content {
		// ShortTag is an alias's target's, so *n with &n ~ is caught too.
		if item.ShortTag() == "!!null" {
			_, err := str(item)
			return entryErr(item, err)
		}
	}
	return n.Decode((*[]T)(l))
}

type hostPattern struct{ netguard.HostPattern }

func (p *hostPattern) UnmarshalYAML(n *yaml.Node) error {
	s, err := str(n)
	if err == nil {
		p.HostPattern, err = netguard.ParseHostPattern(s)
	}
	return entryErr(n, err)
}

type addrRange struct{ netip.Prefix }

func (r *addrRange) UnmarshalYAML(n *yaml.Node) error {
	s, err := str(n)
	if err == nil {
		r.Prefix, err = netguard.ParseAddrRange(s)
	}
	return entryErr(n, err)
}

// str is n as a string, which it must be: 1.5 or true in a host list is a
// mistake, not a host.
func str(n *yaml.Node) (string, error) {
	if n.Kind != yaml.ScalarNode || n.Tag != "!!str" {
		return "", fmt.Errorf("an entry should be a string, not %s", n.ShortTag())
	}
	return n.Value, nil
}

// EntryError is a list entry that isn't valid. yaml stops at the first one.
type EntryError struct {
	Line int
	Err  error
}

func (e *EntryError) Error() string { return fmt.Sprintf("line %d: %s", e.Line, e.Err) }

func (e *EntryError) Unwrap() error { return e.Err }

func entryErr(n *yaml.Node, err error) error {
	if err == nil {
		return nil
	}
	return &EntryError{Line: n.Line, Err: err}
}

// unquotedStar finds a value starting with *, in a block list, a flow list
// or after a key, which YAML reads as an alias, so that the syntax error it
// causes can say so.
var unquotedStar = regexp.MustCompile(`(?m)(^\s*-|[\[,:])\s*\*`)

// badAlias is yaml's syntax error for an alias or anchor name that isn't
// valid, such as the .example.com of *.example.com. Only that error gets the
// hint, so a * in a comment doesn't add it to an unrelated one.
const badAlias = "did not find expected alphabetic or numeric character"

// Parse decodes a policy file. Unknown keys and values of the wrong type are
// reported together, as a *yaml.TypeError; an invalid entry is an
// *EntryError; anything else is a syntax error.
func Parse(data []byte) (netguard.Rules, error) {
	f, err := decodeFile(data)
	if err != nil {
		if strings.Contains(err.Error(), badAlias) && unquotedStar.Match(data) {
			err = fmt.Errorf(`%w (a value starting with * must be quoted, as in "*.example.com")`, err)
		}
		return netguard.Rules{}, err
	}
	// Like an empty list, a null one (every entry commented out under
	// allow_hosts:) would allow every public host.
	if f.AllowHosts == nil && allowHostsNull(data) || f.AllowHosts != nil && len(*f.AllowHosts) == 0 {
		return netguard.Rules{}, errors.New("allow_hosts should not be empty; leave it out to allow every public host")
	}
	var r netguard.Rules
	for _, p := range deref(f.AllowHosts) {
		r.AllowHosts = append(r.AllowHosts, p.HostPattern)
	}
	for _, p := range deref(f.DenyHosts) {
		r.DenyHosts = append(r.DenyHosts, p.HostPattern)
	}
	for _, a := range deref(f.DenyAddrs) {
		r.DenyAddrs = append(r.DenyAddrs, a.Prefix)
	}
	return r, nil
}

// decodeFile decodes data as one YAML document, which may be empty.
func decodeFile(data []byte) (file, error) {
	var f file
	d := yaml.NewDecoder(bytes.NewReader(data))
	d.KnownFields(true)
	if err := d.Decode(&f); err != nil && !errors.Is(err, io.EOF) {
		return file{}, err
	}
	// yaml would ignore a second document, and the rules in it with it.
	var rest yaml.Node
	switch err := d.Decode(&rest); {
	case errors.Is(err, io.EOF):
		return f, nil
	case err != nil:
		return file{}, err
	}
	return file{}, fmt.Errorf("line %d: the policy should be one YAML document, without ---", rest.Line)
}

// allowHostsNull reports whether data has the allow_hosts key with a null
// value, which yaml decodes as the key left out. A custom type can't see it
// either: yaml doesn't call UnmarshalYAML for a null.
func allowHostsNull(data []byte) bool {
	var keys struct {
		AllowHosts yaml.Node `yaml:"allow_hosts"`
	}
	_ = yaml.Unmarshal(data, &keys) // data already decoded once without error
	return keys.AllowHosts.Kind != 0
}

func deref[L ~[]T, T any](p *L) L {
	if p == nil {
		return nil
	}
	return *p
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
