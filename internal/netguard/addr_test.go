package netguard

import (
	"net/netip"
	"testing"
)

func TestPublic(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"172.32.0.1", true}, // just past 172.16.0.0/12
		{"100.128.0.1", true},
		{"0.0.0.0", false},
		{"10.1.2.3", false},
		{"100.64.0.1", false},
		{"127.0.0.1", false},
		{"127.255.255.254", false},
		{"169.254.169.254", false},
		{"172.31.255.255", false},
		{"192.168.1.1", false},
		{"198.18.0.1", false},
		{"203.0.113.7", false},
		{"224.0.0.251", false},
		{"255.255.255.255", false},

		{"2606:4700::1111", true},
		{"2001:4860:4860::8888", true},
		{"::", false},
		{"::1", false},
		{"fc00::1", false},
		{"fd12:3456::1", false},
		{"fe80::1", false},
		{"fe80::1%eth0", false},
		{"fec0::1", false},
		{"ff02::1", false},
		{"2001::1", false}, // Teredo
		{"2001:db8::1", false},
		{"2002:7f00:1::1", false}, // 6to4 of 127.0.0.1
		{"3fff::1", false},
		// IPv4-mapped and NAT64 are judged by the IPv4 address in them.
		{"::ffff:127.0.0.1", false},
		{"::ffff:169.254.169.254", false},
		{"::ffff:10.0.0.1", false},
		{"::ffff:8.8.8.8", true},
		{"::127.0.0.1", false}, // IPv4-compatible, deprecated
		{"64:ff9b::7f00:1", false},
		{"64:ff9b::a9fe:a9fe", false},
		{"64:ff9b::808:808", true},
		{"64:ff9b:1::808:808", false}, // local-use NAT64
	}
	for _, tt := range tests {
		if got := Public(netip.MustParseAddr(tt.ip)); got != tt.want {
			t.Errorf("Public(%s) = %v, want %v", tt.ip, got, tt.want)
		}
	}
	if Public(netip.Addr{}) {
		t.Error("Public(zero Addr) = true, want false")
	}
}
