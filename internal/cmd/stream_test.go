package cmd

import (
	"bytes"
	"encoding/hex"
	"log"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
)

func TestSMCStream(t *testing.T) {
	// set output to a buffer, disable timestamps, reserved, dumps
	var buf bytes.Buffer
	stdout = &buf
	*showTimestamps = false
	*showReserved = false
	*showDumps = false

	// prepare test flows
	net, _ := gopacket.FlowFromEndpoints(layers.NewIPEndpoint(net.IPv4(1,
		2, 3, 4)), layers.NewIPEndpoint(net.IPv4(5, 6, 7, 8)))
	trans, _ := gopacket.FlowFromEndpoints(layers.NewTCPPortEndpoint(123),
		layers.NewTCPPortEndpoint(456))

	// create smcStreamFactory and smcStream with test flows
	var sf smcStreamFactory
	r := sf.New(net, trans)

	// prepare decline message
	declineMsg := "e2d4c3d904001c102525252525252500" +
		"0303000000000000e2d4c3d9"
	msg, err := hex.DecodeString(declineMsg)
	if err != nil {
		log.Fatal(err)
	}

	// put message into stream
	reasm := []tcpassembly.Reassembly{{Bytes: msg}}
	r.Reassembled(reasm)
	r.ReassemblyComplete()

	// check results
	want := "1.2.3.4:123 -> 5.6.7.8:456: Decline: Eyecatcher: SMC-R, " +
		"Type: 4 (Decline), Length: 28, Version: 1, Out of Sync: 0, " +
		"Path: SMC-R, Peer ID: 9509@25:25:25:25:25:00, " +
		"Peer Diagnosis: 0x3030000 (no SMC device found (R or D)), " +
		"Trailer: SMC-R\n"
	got := buf.String()
	if got != want {
		t.Errorf("got = %s; want %s", got, want)
	}
}
