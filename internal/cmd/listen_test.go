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

	"github.com/hwipl/smc-clc/internal/clc"
)

func createFakePacket(sport, dport layers.TCPPort) []byte {
	// prepare creation of fake packet
	pktBuf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// create ethernet header
	mac, err := net.ParseMAC("00:00:00:00:00:00")
	if err != nil {
		log.Fatal(err)
	}
	eth := layers.Ethernet{
		SrcMAC:       mac,
		DstMAC:       mac,
		EthernetType: layers.EthernetTypeIPv4,
	}

	// create ip header
	ip := layers.IPv4{
		Version:  4,
		Flags:    layers.IPv4DontFragment,
		Id:       1,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.IP{127, 0, 0, 1},
		DstIP:    net.IP{127, 0, 0, 1},
	}

	// create tcp header with tcp option
	tcp := layers.TCP{
		SYN:     true,
		ACK:     false,
		SrcPort: sport,
		DstPort: dport,
		Options: []layers.TCPOption{
			{
				OptionType:   254,
				OptionLength: 6,
				OptionData:   clc.SMCREyecatcher,
			},
		},
	}
	tcp.SetNetworkLayerForChecksum(&ip)

	// create payload: clc decline message
	declineMsg := "e2d4c3d904001c102525252525252500" +
		"0303000000000000e2d4c3d9"
	msg, err := hex.DecodeString(declineMsg)
	if err != nil {
		log.Fatal(err)
	}
	payload := gopacket.Payload(msg)

	// create fake packet
	err = gopacket.SerializeLayers(pktBuf, opts, &eth, &ip, &tcp, payload)
	if err != nil {
		log.Fatal(err)
	}
	return pktBuf.Bytes()
}

func TestHandlePacket(t *testing.T) {
	// set output to a buffer, disable timestamps, reserved, dumps
	var buf bytes.Buffer
	stdout = &buf
	*showTimestamps = false
	*showReserved = false
	*showDumps = false

	// Set up assembly
	streamFactory := &smcStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	// init flow table
	flows.init()

	// create fake packet
	packet := gopacket.NewPacket(createFakePacket(123, 456),
		layers.LayerTypeEthernet, gopacket.Default)

	// handle packet
	handlePacket(assembler, packet)

	// check results
	want := "127.0.0.1:123 -> 127.0.0.1:456: Decline: " +
		"Eyecatcher: SMC-R, Type: 4 (Decline), Length: 28, " +
		"Version: 1, Out of Sync: 0, Path: SMC-R, " +
		"Peer ID: 9509@25:25:25:25:25:00, " +
		"Peer Diagnosis: 0x3030000 (no SMC device found (R or D)), " +
		"Trailer: SMC-R\n"
	got := buf.String()
	if got != want {
		t.Errorf("got = %s; want %s", got, want)
	}
}
