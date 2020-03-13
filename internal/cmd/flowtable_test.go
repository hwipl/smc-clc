package cmd

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestFlowTable(t *testing.T) {
	var ft flowTable
	var want bool
	var got bool

	// initialize flow table and test flows
	ft.init()
	net, _ := gopacket.FlowFromEndpoints(layers.NewIPEndpoint(net.IPv4(1,
		2, 3, 4)), layers.NewIPEndpoint(net.IPv4(5, 6, 7, 8)))
	trans, _ := gopacket.FlowFromEndpoints(layers.NewTCPPortEndpoint(123),
		layers.NewTCPPortEndpoint(456))

	// test empty flow table
	want = false
	got = ft.get(net, trans)
	if got != want {
		t.Errorf("ft.get() = %t; want %t", got, want)
	}

	// add entry to flow table
	ft.add(net, trans)
	want = true
	got = ft.get(net, trans)
	if got != want {
		t.Errorf("ft.get() = %t; want %t", got, want)
	}

	// remove entry from flow table
	ft.del(net, trans)
	want = false
	got = ft.get(net, trans)
	if got != want {
		t.Errorf("ft.get() = %t; want %t", got, want)
	}
}
