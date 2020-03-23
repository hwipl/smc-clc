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

type clcPeer struct {
	mac   net.HardwareAddr
	ip    net.IP
	port  uint16
	seq   uint32
	ack   uint32
	flags struct {
		syn bool
		ack bool
		fin bool
	}
	options []layers.TCPOption
}

func newCLCPeer(mac, ip string, port uint16, isn uint32) *clcPeer {
	// parse mac address
	macAddr, err := net.ParseMAC(mac)
	if err != nil {
		log.Fatal(err)
	}

	// parse ip address
	ipAddr := net.ParseIP(ip)

	// create and return peer
	peer := clcPeer{
		mac:  macAddr,
		ip:   ipAddr,
		port: port,
		seq:  isn,
	}
	return &peer
}

type clcConn struct {
	client  *clcPeer
	server  *clcPeer
	packets [][]byte
}

func newCLCConn(client, server *clcPeer) *clcConn {
	conn := clcConn{
		client: client,
		server: server,
	}
	return &conn
}

func (c *clcConn) createSegment(sender, receiver *clcPeer, payload []byte) {
	// prepare creation of fake packet
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// create ethernet header
	eth := layers.Ethernet{
		SrcMAC:       sender.mac,
		DstMAC:       receiver.mac,
		EthernetType: layers.EthernetTypeIPv4,
	}

	// create ip header
	ip := layers.IPv4{
		Version:  4,
		Flags:    layers.IPv4DontFragment,
		Id:       1, // TODO: update? remove?
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    sender.ip,
		DstIP:    receiver.ip,
	}
	// create tcp header
	tcp := layers.TCP{
		SrcPort: layers.TCPPort(sender.port),
		DstPort: layers.TCPPort(receiver.port),
		SYN:     sender.flags.syn,
		ACK:     sender.flags.ack,
		FIN:     sender.flags.fin,
		Seq:     sender.seq,
		Ack:     sender.ack,
		Window:  64000,
	}
	tcp.SetNetworkLayerForChecksum(&ip)

	// add tcp options if present
	if sender.options != nil {
		tcp.Options = sender.options
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

	// append packet to the list of all packets
	packets := make([][]byte, len(c.packets)+1)
	for i, p := range c.packets {
		packets[i] = p
	}
	packets[len(packets)-1] = buf.Bytes()
	c.packets = packets
}

func (c *clcConn) connect() {
	// create tcp option
	options := []layers.TCPOption{
		{
			OptionType:   254,
			OptionLength: 6,
			OptionData:   clc.SMCREyecatcher,
		},
	}

	// create fake SYN packet
	c.client.flags.syn = true
	c.client.flags.ack = false
	c.client.flags.fin = false
	c.client.ack = uint32(0)
	c.client.options = options
	c.createSegment(c.client, c.server, nil)
	c.client.seq += 1

	// create fake SYN, ACK packet
	c.server.flags.syn = true
	c.server.flags.ack = true
	c.server.flags.fin = false
	c.server.ack = c.client.seq
	c.server.options = options
	c.createSegment(c.server, c.client, nil)
	c.server.seq += 1

	// remove options from client and server
	c.client.options = nil
	c.server.options = nil

	// create fake ACK packet
	c.client.flags.syn = false
	c.client.flags.ack = true
	c.client.flags.fin = false
	c.client.ack = c.server.seq
	c.createSegment(c.client, c.server, nil)
}

func (c *clcConn) send(sender, receiver *clcPeer, payload []byte) {
	// create fake payload packet
	sender.flags.syn = false
	sender.flags.ack = true
	sender.flags.fin = false
	sender.ack = receiver.seq
	c.createSegment(sender, receiver, payload)
	sender.seq += uint32(len(payload))

	// create fake ACK packet
	receiver.flags.syn = false
	receiver.flags.ack = true
	receiver.flags.fin = false
	receiver.ack = sender.seq
	c.createSegment(receiver, sender, nil)
}

func (c *clcConn) disconnect() {
	// create fake FIN, ACK packet
	c.client.flags.syn = false
	c.client.flags.ack = true
	c.client.flags.fin = true
	c.client.ack = c.server.seq
	c.createSegment(c.client, c.server, nil)
	c.client.seq += 1

	// create fake FIN, ACK packet
	c.server.flags.syn = false
	c.server.flags.ack = true
	c.server.flags.fin = true
	c.server.ack = c.client.seq
	c.createSegment(c.server, c.client, nil)
	c.server.seq += 1

	// create fake ACK packet
	c.client.flags.syn = false
	c.client.flags.ack = true
	c.client.flags.fin = false
	c.client.ack = c.server.seq
	c.createSegment(c.client, c.server, nil)
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

	// create test payload: clc decline message
	declineMsg := "e2d4c3d904001c102525252525252500" +
		"0303000000000000e2d4c3d9"
	payload, err := hex.DecodeString(declineMsg)
	if err != nil {
		log.Fatal(err)
	}

	// create fake tcp connection with payload
	client := newCLCPeer("00:00:00:00:00:00", "127.0.0.1", 12345, 100)
	server := newCLCPeer("00:00:00:00:00:00", "127.0.0.1", 45678, 100)
	conn := newCLCConn(client, server)
	conn.connect()
	conn.send(client, server, payload)
	conn.disconnect()
	for _, p := range conn.packets {
		packet := gopacket.NewPacket(p,
			layers.LayerTypeEthernet, gopacket.Default)
		handlePacket(assembler, packet)
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

	// create fake tcp connection with payload
	client := newCLCPeer("00:00:00:00:00:00", "127.0.0.1", 123, 100)
	server := newCLCPeer("00:00:00:00:00:00", "127.0.0.1", 456, 100)
	conn := newCLCConn(client, server)
	conn.connect()
	conn.send(client, server, payload)
	conn.disconnect()

	// write packets of fake tcp connection to pcap file
	w := pcapgo.NewWriter(tmpfile)
	w.WriteFileHeader(65536, layers.LinkTypeEthernet)
	for _, packet := range conn.packets {
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
	*pcapFilter = fmt.Sprintf("tcp and port %d and port %d", sport,
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

	// create test payload: clc decline message
	declineMsg := "e2d4c3d904001c102525252525252500" +
		"0303000000000000e2d4c3d9"
	payload, err := hex.DecodeString(declineMsg)
	if err != nil {
		log.Fatal(err)
	}

	// create fake tcp connection with payload
	client := newCLCPeer("00:00:00:00:00:00", "127.0.0.1", uint16(sport),
		100)
	server := newCLCPeer("00:00:00:00:00:00", "127.0.0.1", uint16(dport),
		100)
	conn := newCLCConn(client, server)
	conn.connect()
	conn.send(client, server, payload)
	conn.disconnect()

	// send fake packet
	for _, packet := range conn.packets {
		err = unix.Sendto(fd, packet, 0, &addr)
		if err != nil {
			log.Fatal(err)
		}
	}

	// handle packets with listen
	*pcapMaxPkts = len(conn.packets)
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
