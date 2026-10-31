// Package config is kuzl's policy file: a YAML document built into the
// binary, so that what an agent runs can't change it. The Makefile builds
// the repo's policy.yaml in, or another file:
//
//	make build POLICY=/path/to/policy.yaml
//
// which sets builtin with
//
//	-ldflags "-X github.com/evadcmd/kuzl/internal/config.builtin=$(base64 < policy.yaml | tr -d '\n')"
//
// The file is decoded strictly: an unknown key is an error rather than
// ignored, so a typo such as deny_host can't quietly drop a list.
// policy.yaml lists the keys.
package config

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/netip"
	"regexp"
	"strings"
	"sync"

	"github.com/evadcmd/kuzl/internal/netguard"
	"go.yaml.in/yaml/v3"
)

// builtin is the policy file, base64-encoded, as the build sets it. Empty is
// no file, which allows no host.
var builtin string

const (
	// DefaultMaxStdoutBytes is max_stdout_bytes when the policy leaves it
	// out. Claude Code keeps a tool result in context only up to 50000
	// characters; past that it saves the result to a file and shows a
	// preview. A byte is at most a character, and 48000 leaves room for what
	// the caller adds, such as kuzl's truncation note and, on an error,
	// stderr.
	DefaultMaxStdoutBytes = 48000
	// maxStdoutLimit is the most max_stdout_bytes may be: what is shown is
	// held in memory, and -o downloads no more either.
	maxStdoutLimit = 100 << 20
)

// Policy is what the policy file sets.
type Policy struct {
	netguard.Rules
	// MaxStdoutBytes caps what curl writes to stdout, headers included.
	MaxStdoutBytes int
}

// file is the policy file. A pointer field is an optional key: nil is the
// key left out, or set to null.
type file struct {
	// AllowHosts are the only hosts requests may go to; "*" is every public
	// host. Left out, empty or null, no host is.
	AllowHosts *list[hostPattern] `yaml:"allow_hosts"`
	// DenyHosts are refused, even if AllowHosts matches them.
	DenyHosts *list[hostPattern] `yaml:"deny_hosts"`
	// DenyAddrs are IPs and CIDR prefixes refused on top of the non-public
	// addresses, checked on the address dialed.
	DenyAddrs *list[addrRange] `yaml:"deny_addrs"`
	// MaxStdoutBytes caps curl's stdout; left out or null, it is
	// DefaultMaxStdoutBytes.
	MaxStdoutBytes *byteCount `yaml:"max_stdout_bytes"`
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

// byteCount is max_stdout_bytes: a whole number, from 1 to maxStdoutLimit.
type byteCount int

func (c *byteCount) UnmarshalYAML(n *yaml.Node) error {
	// yaml doesn't resolve an integer past int64 as !!int: past uint64 it is
	// !!float, and between the two it is an !!int that fails to decode into
	// an int. Either way it is a number of bytes, only too many.
	if n.Kind == yaml.ScalarNode && n.Style == 0 {
		if i, ok := new(big.Int).SetString(n.Value, 0); ok && (i.Sign() < 1 || i.Cmp(big.NewInt(maxStdoutLimit)) > 0) {
			return entryErr(n, fmt.Errorf("max_stdout_bytes %s: want 1 to %d", n.Value, maxStdoutLimit))
		}
	}
	if n.Kind != yaml.ScalarNode || n.ShortTag() != "!!int" {
		return entryErr(n, fmt.Errorf("max_stdout_bytes should be a number of bytes, not %s", n.ShortTag()))
	}
	var v int
	if err := n.Decode(&v); err != nil {
		return entryErr(n, err)
	}
	if v < 1 || v > maxStdoutLimit {
		return entryErr(n, fmt.Errorf("max_stdout_bytes %s: want 1 to %d", n.Value, maxStdoutLimit))
	}
	*c = byteCount(v)
	return nil
}

// str is n as a string, which it must be: 1.5 or true in a host list is a
// mistake, not a host.
func str(n *yaml.Node) (string, error) {
	if n.Kind != yaml.ScalarNode || n.Tag != "!!str" {
		return "", fmt.Errorf("an entry should be a string, not %s", n.ShortTag())
	}
	return n.Value, nil
}

// EntryError is a list entry, or a value, that isn't valid. yaml stops at the
// first one.
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
func Parse(data []byte) (Policy, error) {
	f, err := decodeFile(data)
	if err != nil {
		if strings.Contains(err.Error(), badAlias) && unquotedStar.Match(data) {
			err = fmt.Errorf(`%w (a value starting with * must be quoted, as in "*.example.com")`, err)
		}
		return Policy{}, err
	}
	p := Policy{MaxStdoutBytes: DefaultMaxStdoutBytes}
	for _, h := range deref(f.AllowHosts) {
		p.AllowHosts = append(p.AllowHosts, h.HostPattern)
	}
	for _, h := range deref(f.DenyHosts) {
		p.DenyHosts = append(p.DenyHosts, h.HostPattern)
	}
	for _, a := range deref(f.DenyAddrs) {
		p.DenyAddrs = append(p.DenyAddrs, a.Prefix)
	}
	if f.MaxStdoutBytes != nil {
		p.MaxStdoutBytes = int(*f.MaxStdoutBytes)
	}
	return p, nil
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

func deref[L ~[]T, T any](p *L) L {
	if p == nil {
		return nil
	}
	return *p
}

// Builtin returns the policy file built into the binary. It decodes it once:
// builtin is set at link time, so every call returns the same result.
var Builtin = sync.OnceValues(func() (Policy, error) {
	return decode(builtin)
})

func decode(encoded string) (Policy, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return Policy{}, fmt.Errorf("the built-in policy is not base64 (build with make build POLICY=...): %w", err)
	}
	p, err := Parse(data)
	if err != nil {
		return Policy{}, fmt.Errorf("the built-in policy: %w", err)
	}
	return p, nil
}

// Format writes p as a policy file, in normalized form: for a p that Parse
// returned, Parse(Format(p)) returns p. (Not for any p: the zero Policy's
// max_stdout_bytes 0 doesn't parse.)
func Format(p Policy) []byte {
	r := p.Rules
	var out struct {
		AllowHosts     []string `yaml:"allow_hosts"`
		DenyHosts      []string `yaml:"deny_hosts"`
		DenyAddrs      []string `yaml:"deny_addrs"`
		MaxStdoutBytes int      `yaml:"max_stdout_bytes"`
	}
	out.AllowHosts, out.DenyHosts, out.DenyAddrs = []string{}, []string{}, []string{}
	out.MaxStdoutBytes = p.MaxStdoutBytes
	for _, h := range r.AllowHosts {
		out.AllowHosts = append(out.AllowHosts, h.String())
	}
	for _, h := range r.DenyHosts {
		out.DenyHosts = append(out.DenyHosts, h.String())
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
		b.WriteString("# allow_hosts is empty: no host is allowed.\n")
	}
	e := yaml.NewEncoder(&b)
	e.SetIndent(2)
	if err := errors.Join(e.Encode(out), e.Close()); err != nil {
		panic(err) // a struct of string lists and an int always encodes
	}
	return b.Bytes()
}
