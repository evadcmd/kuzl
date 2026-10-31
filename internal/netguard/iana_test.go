package netguard

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

// IANA's special-purpose registries, which nonPublic4 and nonPublic6 follow.
// TestIANA checks them on a schedule (.github/workflows/iana.yml), not on
// every run, so that go test stays offline.
const (
	ianaIPv4 = "https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry-1.csv"
	ianaIPv6 = "https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry-1.csv"
)

// mapped4 is the IPv4-mapped form, which canonical turns into IPv4.
var mapped4 = netip.MustParsePrefix("::ffff:0:0/96")

// ianaExceptions are registry rows, not globally reachable, that Public
// doesn't refuse as a range, each with the reason.
var ianaExceptions = map[netip.Prefix]string{
	mapped4: "judged by the IPv4 address in it (canonical)",
}

// ianaRow is one address block of a registry row. A row may list more than
// one block.
type ianaRow struct {
	prefix netip.Prefix
	// reachable is the "Globally Reachable" value without its footnote:
	// True, False, N/A, or empty for a terminated row.
	reachable string
	line      int
}

// parseRegistry reads a registry CSV, finding its columns by their header.
func parseRegistry(r io.Reader) ([]ianaRow, error) {
	cr := csv.NewReader(r)
	header, err := cr.Read()
	if err != nil {
		return nil, fmt.Errorf("header: %w", err)
	}
	block, reach := -1, -1
	for i, h := range header {
		switch strings.TrimPrefix(h, "\ufeff") {
		case "Address Block":
			block = i
		case "Globally Reachable":
			reach = i
		}
	}
	if block < 0 || reach < 0 {
		return nil, fmt.Errorf("header %q: no Address Block or Globally Reachable column", header)
	}
	var rows []ianaRow
	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		line, _ := cr.FieldPos(block)
		// "False [1]": a value may carry a footnote.
		reachable, _, _ := strings.Cut(rec[reach], " ")
		// "192.0.0.0/24 [2]", "192.0.0.170/32, 192.0.0.171/32".
		for s := range strings.SplitSeq(rec[block], ",") {
			s, _, _ = strings.Cut(strings.TrimSpace(s), " ")
			p, err := netip.ParsePrefix(s)
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", line, err)
			}
			rows = append(rows, ianaRow{prefix: p, reachable: reachable, line: line})
		}
	}
	if len(rows) == 0 {
		return nil, errors.New("no rows")
	}
	return rows, nil
}

// refusesAll reports whether Public refuses every address in p.
func refusesAll(p netip.Prefix) bool {
	if p.Addr().Is4() {
		return within(p, nonPublic4)
	}
	// Outside global6 everything is refused, apart from the forms canonical
	// turns into IPv4.
	if p.Bits() >= global6.Bits() && !global6.Contains(p.Addr()) &&
		!p.Overlaps(mapped4) && !p.Overlaps(nat64) {
		return true
	}
	return within(p, nonPublic6)
}

// within reports whether one of ps contains all of p.
func within(p netip.Prefix, ps []netip.Prefix) bool {
	for _, q := range ps {
		if q.Bits() <= p.Bits() && q.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

// unrefused returns the rows not marked globally reachable that Public
// doesn't refuse in full, leaving out ianaExceptions. Only this direction is
// checked: kuzl refuses more than IANA lists (all of 2001::/23, say).
func unrefused(rows []ianaRow) []ianaRow {
	var out []ianaRow
	for _, r := range rows {
		if r.reachable == "True" {
			continue
		}
		if _, ok := ianaExceptions[r.prefix]; ok {
			continue
		}
		if !refusesAll(r.prefix) {
			out = append(out, r)
		}
	}
	return out
}

// TestIANA downloads the registries and fails on a range that isn't globally
// reachable but that Public allows. It runs only with KUZL_IANA_CHECK=1.
func TestIANA(t *testing.T) {
	if os.Getenv("KUZL_IANA_CHECK") != "1" {
		t.Skip("downloads from iana.org; set KUZL_IANA_CHECK=1 to run")
	}
	for _, url := range []string{ianaIPv4, ianaIPv6} {
		rows, err := fetchRegistry(t.Context(), url)
		if err != nil {
			t.Fatalf("%s: %v", url, err)
		}
		t.Logf("%s: %d blocks", url, len(rows))
		for _, r := range unrefused(rows) {
			t.Errorf("%s line %d: %s (Globally Reachable %q) isn't refused; add it to addr.go or ianaExceptions",
				url, r.line, r.prefix, r.reachable)
		}
	}
}

func fetchRegistry(ctx context.Context, url string) ([]ianaRow, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "kuzl-iana-check (+https://github.com/evadcmd/kuzl)")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %s", resp.Status)
	}
	return parseRegistry(resp.Body)
}

// The fixtures are the registries as of 2026-10, which addr.go covers.
func TestIANAFixtures(t *testing.T) {
	for _, name := range []string{"testdata/iana-ipv4-special-registry-1.csv", "testdata/iana-ipv6-special-registry-1.csv"} {
		f, err := os.Open(name) //nolint:gosec // G304: a fixture path from the list above.
		if err != nil {
			t.Fatal(err)
		}
		rows, err := parseRegistry(f)
		_ = f.Close()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, r := range unrefused(rows) {
			t.Errorf("%s line %d: %s isn't refused", name, r.line, r.prefix)
		}
	}
}

func TestParseRegistry(t *testing.T) {
	const in = `Address Block,Name,Globally Reachable
0.0.0.0/8,"""This network",False
"192.0.0.170/32, 192.0.0.171/32",NAT64/DNS64 Discovery,False
192.0.0.0/24 [2],IETF Protocol Assignments,False [1]
2001:10::/28,Deprecated (previously ORCHID),
`
	rows, err := parseRegistry(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	want := []ianaRow{
		{netip.MustParsePrefix("0.0.0.0/8"), "False", 2},
		{netip.MustParsePrefix("192.0.0.170/32"), "False", 3},
		{netip.MustParsePrefix("192.0.0.171/32"), "False", 3},
		{netip.MustParsePrefix("192.0.0.0/24"), "False", 4},
		{netip.MustParsePrefix("2001:10::/28"), "", 5},
	}
	if fmt.Sprint(rows) != fmt.Sprint(want) {
		t.Errorf("parseRegistry = %v, want %v", rows, want)
	}

	for _, in := range []string{
		"",
		"Address Block,Name\n10.0.0.0/8,Private-Use\n",
		"Address Block,Globally Reachable\n",
		"Address Block,Globally Reachable\n10.0.0.0/33,False\n",
		"<!DOCTYPE html>\n<html></html>\n",
	} {
		if _, err := parseRegistry(strings.NewReader(in)); err == nil {
			t.Errorf("parseRegistry(%q) = nil error", in)
		}
	}
}

func TestUnrefused(t *testing.T) {
	tests := []struct {
		prefix    string
		reachable string
		want      bool // reported
	}{
		{"10.0.0.0/8", "False", false},
		{"10.1.0.0/16", "False", false},    // inside a nonPublic4 prefix
		{"10.0.0.0/7", "False", true},      // wider than 10.0.0.0/8
		{"192.31.196.0/24", "True", false}, // reachable: not checked
		{"192.31.196.0/24", "False", true},
		{"192.88.99.0/24", "", false}, // terminated, still refused
		{"192.0.2.0/23", "N/A", true}, // wider than 192.0.2.0/24

		{"fc00::/7", "False", false},       // outside global6
		{"5f00::/16", "False", false},      // outside global6
		{"2001:3::/32", "False", false},    // inside 2001::/23
		{"2001:200::/23", "False", true},   // just past 2001::/23
		{"3fff::/20", "False", false},      // nonPublic6
		{"::ffff:0:0/96", "False", false},  // exception
		{"::ffff:0:0/104", "False", true},  // judged as IPv4: not an exception
		{"64:ff9b::/96", "False", true},    // NAT64, judged as IPv4
		{"64:ff9b:1::/48", "False", false}, // local-use NAT64, refused
		{"::/0", "False", true},            // overlaps global6
	}
	for _, tt := range tests {
		got := unrefused([]ianaRow{{prefix: netip.MustParsePrefix(tt.prefix), reachable: tt.reachable}})
		if (len(got) > 0) != tt.want {
			t.Errorf("unrefused(%s, %q) reported = %v, want %v", tt.prefix, tt.reachable, len(got) > 0, tt.want)
		}
	}
}
