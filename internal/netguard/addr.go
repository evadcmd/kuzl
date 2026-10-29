package netguard

import "net/netip"

// nonPublic4 are the IPv4 ranges that aren't on the public internet, from
// IANA's special-purpose registry (RFC 6890 and its updates).
var nonPublic4 = prefixes(
	"0.0.0.0/8",       // "this network", 0.0.0.0 included
	"10.0.0.0/8",      // private (RFC 1918)
	"100.64.0.0/10",   // CGNAT shared space (RFC 6598)
	"127.0.0.0/8",     // loopback
	"169.254.0.0/16",  // link-local, the cloud metadata endpoint included
	"172.16.0.0/12",   // private (RFC 1918)
	"192.0.0.0/24",    // IETF protocol assignments
	"192.0.2.0/24",    // documentation (TEST-NET-1)
	"192.88.99.0/24",  // deprecated 6to4 relay anycast
	"192.168.0.0/16",  // private (RFC 1918)
	"198.18.0.0/15",   // benchmarking, often used inside networks
	"198.51.100.0/24", // documentation (TEST-NET-2)
	"203.0.113.0/24",  // documentation (TEST-NET-3)
	"224.0.0.0/4",     // multicast
	"240.0.0.0/4",     // reserved, the broadcast address included
)

var (
	// global6 is IPv6 global unicast; everything outside it (loopback,
	// unspecified, ULA, link-local, site-local, multicast, the IPv4-mapped
	// and -compatible forms) isn't public, apart from NAT64 below.
	global6 = netip.MustParsePrefix("2000::/3")
	// nonPublic6 are the ranges inside global6 that aren't public either.
	nonPublic6 = prefixes(
		"2001::/23",     // IETF protocol assignments, Teredo included
		"2001:db8::/32", // documentation
		"2002::/16",     // 6to4, which embeds an IPv4 address
		"3fff::/20",     // documentation (RFC 9637)
	)
	// nat64 is the well-known NAT64 prefix (RFC 6052): the IPv4 address in
	// its last 32 bits is the one reached, so that is what is checked.
	nat64 = netip.MustParsePrefix("64:ff9b::/96")
)

func prefixes(ss ...string) []netip.Prefix {
	ps := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		ps[i] = netip.MustParsePrefix(s)
	}
	return ps
}

// Public reports whether ip is on the public internet, the only addresses
// kuzl dials. An IPv4-mapped IPv6 address is judged as the IPv4 address it
// maps, so ::ffff:127.0.0.1 is loopback.
func Public(ip netip.Addr) bool {
	ip = ip.WithZone("").Unmap()
	if ip.Is4() {
		return !inAny(nonPublic4, ip)
	}
	if nat64.Contains(ip) {
		b := ip.As16()
		return Public(netip.AddrFrom4([4]byte(b[12:])))
	}
	return global6.Contains(ip) && !inAny(nonPublic6, ip)
}

func inAny(ps []netip.Prefix, ip netip.Addr) bool {
	for _, p := range ps {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}
