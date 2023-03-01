package cmd

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/gopacket/gopacket/tcpassembly"

	"github.com/hwipl/packet-go/pkg/tcp"
	"github.com/hwipl/smc-go/pkg/clc"
)

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

	// init handler
	handler := handler{
		assembler: assembler,
	}

	// create test payload: clc decline message
	declineMsg := "e2d4c3d904001c102525252525252500" +
		"0303000000000000e2d4c3d9"
	payload, err := hex.DecodeString(declineMsg)
	if err != nil {
		log.Fatal(err)
	}

	// create smc tcp option
	var options = []layers.TCPOption{
		{
			OptionType:   254,
			OptionLength: 6,
			OptionData:   clc.SMCREyecatcher,
		},
	}

	// create fake tcp connection with payload
	client := tcp.NewPeer("00:00:00:00:00:00", "127.0.0.1", 12345, 100)
	server := tcp.NewPeer("00:00:00:00:00:00", "127.0.0.1", 45678, 100)
	conn := tcp.NewConn(client, server)
	conn.Options.SYN = options
	conn.Options.SYNACK = options
	conn.Connect()
	conn.Send(client, server, payload)
	conn.Disconnect()
	for _, p := range conn.Packets {
		packet := gopacket.NewPacket(p,
			layers.LayerTypeEthernet, gopacket.Default)
		handler.HandlePacket(packet)
	}

	// check results
	want := "127.0.0.1:12345 -> 127.0.0.1:45678: Decline: " +
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

func TestListenPcap(t *testing.T) {
	// set output to a buffer, disable timestamps, reserved, dumps
	var buf bytes.Buffer
	stdout = &buf
	log.SetOutput(&buf)
	*showTimestamps = false
	*showReserved = false
	*showDumps = false

	// create temporary pcap file
	tmpfile, err := ioutil.TempFile("", "decline.pcap")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	// create test payload: clc decline message
	declineMsg := "e2d4c3d904001c102525252525252500" +
		"0303000000000000e2d4c3d9"
	payload, err := hex.DecodeString(declineMsg)
	if err != nil {
		log.Fatal(err)
	}

	// create smc tcp option
	var options = []layers.TCPOption{
		{
			OptionType:   254,
			OptionLength: 6,
			OptionData:   clc.SMCREyecatcher,
		},
	}

	// create fake tcp connection with payload
	client := tcp.NewPeer("00:00:00:00:00:00", "127.0.0.1", 123, 100)
	server := tcp.NewPeer("00:00:00:00:00:00", "127.0.0.1", 456, 100)
	conn := tcp.NewConn(client, server)
	conn.Options.SYN = options
	conn.Options.SYNACK = options
	conn.Connect()
	conn.Send(client, server, payload)
	conn.Disconnect()

	// write packets of fake tcp connection to pcap file
	w := pcapgo.NewWriter(tmpfile)
	w.WriteFileHeader(65536, layers.LinkTypeEthernet)
	for _, packet := range conn.Packets {
		w.WritePacket(gopacket.CaptureInfo{
			CaptureLength: len(packet),
			Length:        len(packet),
		}, packet)
	}
	tmpfile.Close()

	// test listen() with pcap file
	*pcapFile = tmpfile.Name()
	listen()

	// check results
	want := fmt.Sprintf("Reading packets from file %s:\n",
		tmpfile.Name()) +
		"127.0.0.1:123 -> 127.0.0.1:456: Decline: " +
		"Eyecatcher: SMC-R, Type: 4 (Decline), Length: 28, " +
		"Version: 1, Out of Sync: 0, Path: SMC-R, " +
		"Peer ID: 9509@25:25:25:25:25:00, " +
		"Peer Diagnosis: 0x3030000 (no SMC device found (R or D)), " +
		"Trailer: SMC-R\n"
	got := buf.String()[20:] // ignore date and time
	if got != want {
		t.Errorf("got = %s; want %s", got, want)
	}

	// test with filter
	*pcapFilter = "tcp and port 123"
	buf.Reset()
	listen()

	// check results
	want = fmt.Sprintf("Reading packets from file %s:\n",
		tmpfile.Name()) +
		"127.0.0.1:123 -> 127.0.0.1:456: Decline: " +
		"Eyecatcher: SMC-R, Type: 4 (Decline), Length: 28, " +
		"Version: 1, Out of Sync: 0, Path: SMC-R, " +
		"Peer ID: 9509@25:25:25:25:25:00, " +
		"Peer Diagnosis: 0x3030000 (no SMC device found (R or D)), " +
		"Trailer: SMC-R\n"
	got = buf.String()[20:] // ignore date and time
	if got != want {
		t.Errorf("got = %s; want %s", got, want)
	}

	// test with filter that does not match any packets
	*pcapFilter = "tcp and port 12345"
	buf.Reset()
	listen()

	// check results
	want = fmt.Sprintf("Reading packets from file %s:\n",
		tmpfile.Name())
	got = buf.String()[20:] // ignore date and time
	if got != want {
		t.Errorf("got = %s; want %s", got, want)
	}
}
