package cmd

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/gopacket/tcpassembly"
	"golang.org/x/sys/unix"

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

func createFakeConnPkt(eth layers.Ethernet, ip layers.IPv4,
	sport, dport layers.TCPPort, SYN, ACK, FIN bool, seq, ack uint32,
	options []layers.TCPOption, payload []byte) []byte {
	// prepare creation of fake packet
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// create tcp header
	tcp := layers.TCP{
		SrcPort: sport,
		DstPort: dport,
		SYN:     SYN,
		ACK:     ACK,
		FIN:     FIN,
		Seq:     seq,
		Ack:     ack,
		Window:  64000,
	}
	tcp.SetNetworkLayerForChecksum(&ip)

	// add tcp options if present
	if options != nil {
		tcp.Options = options
	}

	// serialize packet to buffer
	var err error
	buf := gopacket.NewSerializeBuffer()
	if payload != nil {
		// with payload
		pl := gopacket.Payload(payload)
		err = gopacket.SerializeLayers(buf, opts, &eth, &ip, &tcp,
			pl)
	} else {
		// without payload
		err = gopacket.SerializeLayers(buf, opts, &eth, &ip, &tcp)
	}
	if err != nil {
		log.Fatal(err)
	}

	// return buffer as bytes
	return buf.Bytes()
}

func createFakeConn(cliPort, srvPort layers.TCPPort) [][]byte {
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

	// create tcp option
	options := []layers.TCPOption{
		{
			OptionType:   254,
			OptionLength: 6,
			OptionData:   clc.SMCREyecatcher,
		},
	}

	// create packets of fake connection
	packets := make([][]byte, 8)

	// create fake SYN packet
	isn := uint32(100)
	sport := cliPort
	dport := srvPort
	SYN := true
	ACK := false
	FIN := false
	seq := isn
	ack := uint32(0)
	packets[0] = createFakeConnPkt(eth, ip, sport, dport, SYN, ACK, FIN,
		seq, ack, options, nil)

	// create fake SYN, ACK packet
	sport = srvPort
	dport = cliPort
	SYN = true
	ACK = true
	seq = isn
	ack = isn + 1
	packets[1] = createFakeConnPkt(eth, ip, sport, dport, SYN, ACK, FIN,
		seq, ack, options, nil)

	// create fake ACK packet
	sport = cliPort
	dport = srvPort
	SYN = false
	ACK = true
	seq = isn + 1
	ack = isn + 1
	packets[2] = createFakeConnPkt(eth, ip, sport, dport, SYN, ACK, FIN,
		seq, ack, nil, nil)

	// create payload: clc decline message
	declineMsg := "e2d4c3d904001c102525252525252500" +
		"0303000000000000e2d4c3d9"
	msg, err := hex.DecodeString(declineMsg)
	if err != nil {
		log.Fatal(err)
	}

	// create fake payload packet
	packets[3] = createFakeConnPkt(eth, ip, sport, dport, SYN, ACK, FIN,
		seq, ack, nil, msg)

	// create fake ACK packet
	sport = srvPort
	dport = cliPort
	SYN = false
	ACK = true
	seq = isn + 1
	ack = isn + 1 + uint32(len(msg))
	packets[4] = createFakeConnPkt(eth, ip, sport, dport, SYN, ACK, FIN,
		seq, ack, nil, nil)

	// create fake FIN, ACK packet
	sport = cliPort
	dport = srvPort
	FIN = true
	ACK = true
	seq = isn + 1 + uint32(len(msg))
	ack = isn + 1
	packets[5] = createFakeConnPkt(eth, ip, sport, dport, SYN, ACK, FIN,
		seq, ack, nil, nil)

	// create fake FIN, ACK packet
	sport = srvPort
	dport = cliPort
	FIN = true
	ACK = true
	seq = isn + 1
	ack = isn + 1 + uint32(len(msg)) + 1
	packets[6] = createFakeConnPkt(eth, ip, sport, dport, SYN, ACK, FIN,
		seq, ack, nil, nil)

	// create fake ACK packet
	sport = cliPort
	dport = srvPort
	FIN = false
	ACK = true
	seq = isn + 1 + uint32(len(msg)) + 1
	ack = isn + 1 + 1
	packets[7] = createFakeConnPkt(eth, ip, sport, dport, SYN, ACK, FIN,
		seq, ack, nil, nil)

	return packets
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

	// create fake tcp connection
	buf.Reset()
	conn := createFakeConn(12345, 45678)
	for _, p := range conn {
		packet = gopacket.NewPacket(p,
			layers.LayerTypeEthernet, gopacket.Default)
		handlePacket(assembler, packet)
	}

	// check results
	want = "127.0.0.1:12345 -> 127.0.0.1:45678: Decline: " +
		"Eyecatcher: SMC-R, Type: 4 (Decline), Length: 28, " +
		"Version: 1, Out of Sync: 0, Path: SMC-R, " +
		"Peer ID: 9509@25:25:25:25:25:00, " +
		"Peer Diagnosis: 0x3030000 (no SMC device found (R or D)), " +
		"Trailer: SMC-R\n"
	got = buf.String()
	if got != want {
		t.Errorf("got = %s; want %s", got, want)
	}
}

func TestListenPcap(t *testing.T) {
	// set output to a buffer, disable timestamps, reserved, dumps
	var buf bytes.Buffer
	stdout = &buf
	*showTimestamps = false
	*showReserved = false
	*showDumps = false

	// create temporary pcap file
	tmpfile, err := ioutil.TempFile("", "decline.pcap")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	// create fake packet
	packet := createFakePacket(123, 456)

	// write fake packet to pcap file
	w := pcapgo.NewWriter(tmpfile)
	w.WriteFileHeader(65536, layers.LinkTypeEthernet)
	w.WritePacket(gopacket.CaptureInfo{
		CaptureLength: len(packet),
		Length:        len(packet),
	}, packet)
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
	got := buf.String()
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
	got = buf.String()
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
	got = buf.String()
	if got != want {
		t.Errorf("got = %s; want %s", got, want)
	}
}

func TestListenLoopback(t *testing.T) {
	// skip this test as non-root user
	uid := os.Getuid()
	if uid != 0 {
		t.Skip("This test requires root privileges.")
	}

	// set output to a buffer, disable timestamps, reserved, dumps
	var buf bytes.Buffer
	stdout = &buf
	*showTimestamps = false
	*showReserved = false
	*showDumps = false

	// "reserve" random source port
	sportListener, err := net.Listen("tcp", ":0")
	if err != nil {
		log.Fatal(err)
	}
	defer sportListener.Close()
	sport := sportListener.Addr().(*net.TCPAddr).Port

	// "reserve" random destination port
	dportListener, err := net.Listen("tcp", ":0")
	if err != nil {
		log.Fatal(err)
	}
	defer dportListener.Close()
	dport := dportListener.Addr().(*net.TCPAddr).Port

	// prepare listen with loopback device, set a timeout to avoid hanging
	// in pcap capturing, and set the filter to only capture packets from
	// the source port to the destination port
	*pcapFile = ""
	*pcapDevice = "lo"
	*pcapTimeout = 1
	*pcapFilter = fmt.Sprintf("tcp and src port %d and dst port %d", sport,
		dport)
	assembler, pcapHandle := listenPrepare()
	defer pcapHandle.Close()

	// create raw socket
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, unix.ETH_P_ALL)
	if err != nil {
		log.Fatal(err)
	}
	defer unix.Close(fd)

	// get loopback interface
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		log.Fatal(err)
	}

	// create sockaddr
	addr := unix.SockaddrLinklayer{
		Protocol: unix.ETH_P_IP,
		Ifindex:  lo.Index,
		Halen:    6,
	}

	// create fake packet
	packet := createFakePacket(layers.TCPPort(sport),
		layers.TCPPort(dport))

	// send fake packet
	err = unix.Sendto(fd, packet, 0, &addr)
	if err != nil {
		log.Fatal(err)
	}

	// handle packets with listen
	*pcapMaxPkts = 1
	*pcapMaxTime = 1
	listenLoop(assembler, pcapHandle)

	// check results
	want := "Listening on interface lo:\n" +
		fmt.Sprintf("127.0.0.1:%d -> 127.0.0.1:%d: Decline: ", sport,
			dport) +
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
