package cmd

import (
	"bytes"
	"encoding/hex"
	"log"
	"net"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/hwipl/smc-go/pkg/clc"
)

func TestPrintCLC(t *testing.T) {
	var want, got string

	// prepare test flows
	net, _ := gopacket.FlowFromEndpoints(layers.NewIPEndpoint(net.IPv4(1,
		2, 3, 4)), layers.NewIPEndpoint(net.IPv4(5, 6, 7, 8)))
	trans, _ := gopacket.FlowFromEndpoints(layers.NewTCPPortEndpoint(123),
		layers.NewTCPPortEndpoint(456))

	// prepare decline message
	declineMsg := "e2d4c3d904001c102525252525252500" +
		"0303000000000000e2d4c3d9"
	msg, err := hex.DecodeString(declineMsg)
	if err != nil {
		log.Fatal(err)
	}
	clcMsg, _ := clc.NewMessage(msg)
	clcMsg.Parse(msg)

	// set output to a buffer
	var buf bytes.Buffer
	stdout = &buf

	// test output without timestamps, without reserved, without dumps
	*showTimestamps = false
	*showReserved = false
	*showDumps = false

	buf.Reset()
	printCLC(net, trans, clcMsg)
	want = "1.2.3.4:123 -> 5.6.7.8:456: Decline: Eyecatcher: SMC-R, " +
		"Type: 4 (Decline), Length: 28, Version: 1, Out of Sync: 0, " +
		"Path: SMC-R, Peer ID: 9509@25:25:25:25:25:00, " +
		"Peer Diagnosis: 0x3030000 (no SMC device found (R or D)), " +
		"Trailer: SMC-R\n"
	got = buf.String()
	if got != want {
		t.Errorf("got = %s; want %s", got, want)
	}

	// test output without timestamps, without reserved, with dumps
	*showTimestamps = false
	*showReserved = false
	*showDumps = true

	buf.Reset()
	printCLC(net, trans, clcMsg)
	want = "1.2.3.4:123 -> 5.6.7.8:456: Decline: Eyecatcher: SMC-R, " +
		"Type: 4 (Decline), Length: 28, Version: 1, Out of Sync: 0, " +
		"Path: SMC-R, Peer ID: 9509@25:25:25:25:25:00, " +
		"Peer Diagnosis: 0x3030000 (no SMC device found (R or D)), " +
		"Trailer: SMC-R\n" +
		"00000000  e2 d4 c3 d9 04 00 1c 10  " +
		"25 25 25 25 25 25 25 00  |........%%%%%%%.|\n" +
		"00000010  03 03 00 00 00 00 00 00  " +
		"e2 d4 c3 d9              |............|\n"
	got = buf.String()
	if got != want {
		t.Errorf("got = %s; want %s", got, want)
	}

	// test output without timestamps, with reserved, without dumps
	*showTimestamps = false
	*showReserved = true
	*showDumps = false

	buf.Reset()
	printCLC(net, trans, clcMsg)
	want = "1.2.3.4:123 -> 5.6.7.8:456: Decline: Eyecatcher: SMC-R, " +
		"Type: 4 (Decline), Length: 28, Version: 1, Out of Sync: 0, " +
		"Reserved: 0x0, Path: SMC-R, " +
		"Peer ID: 9509@25:25:25:25:25:00, " +
		"Peer Diagnosis: 0x3030000 (no SMC device found (R or D)), " +
		"Reserved: 0x00000000, Trailer: SMC-R\n"
	got = buf.String()
	if got != want {
		t.Errorf("got = %s; want %s", got, want)
	}

	// test output without timestamps, with reserved, with dumps
	*showTimestamps = false
	*showReserved = true
	*showDumps = true

	buf.Reset()
	printCLC(net, trans, clcMsg)
	want = "1.2.3.4:123 -> 5.6.7.8:456: Decline: Eyecatcher: SMC-R, " +
		"Type: 4 (Decline), Length: 28, Version: 1, Out of Sync: 0, " +
		"Reserved: 0x0, Path: SMC-R, " +
		"Peer ID: 9509@25:25:25:25:25:00, " +
		"Peer Diagnosis: 0x3030000 (no SMC device found (R or D)), " +
		"Reserved: 0x00000000, Trailer: SMC-R\n" +
		"00000000  e2 d4 c3 d9 04 00 1c 10  " +
		"25 25 25 25 25 25 25 00  |........%%%%%%%.|\n" +
		"00000010  03 03 00 00 00 00 00 00  " +
		"e2 d4 c3 d9              |............|\n"
	got = buf.String()
	if got != want {
		t.Errorf("got = %s; want %s", got, want)
	}

	// test output with timestamps, with reserved, with dumps
	*showTimestamps = true
	*showReserved = true
	*showDumps = true

	buf.Reset()
	printCLC(net, trans, clcMsg)
	want = "1.2.3.4:123 -> 5.6.7.8:456: Decline: Eyecatcher: SMC-R, " +
		"Type: 4 (Decline), Length: 28, Version: 1, Out of Sync: 0, " +
		"Reserved: 0x0, Path: SMC-R, " +
		"Peer ID: 9509@25:25:25:25:25:00, " +
		"Peer Diagnosis: 0x3030000 (no SMC device found (R or D)), " +
		"Reserved: 0x00000000, Trailer: SMC-R\n" +
		"00000000  e2 d4 c3 d9 04 00 1c 10  " +
		"25 25 25 25 25 25 25 00  |........%%%%%%%.|\n" +
		"00000010  03 03 00 00 00 00 00 00  " +
		"e2 d4 c3 d9              |............|\n"
	got = buf.String()[16:] // ignore timestamp
	if got != want {
		t.Errorf("got = %s; want %s", got, want)
	}
}
