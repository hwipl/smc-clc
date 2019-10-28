package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

var (
	// pcap variables
	pcapDevice  = flag.String("i", "eth0", "the interface to listen on")
	pcapPromisc = flag.Bool("promisc", true, "promiscuous mode")

	// flow table
	flows = make(map[gopacket.Flow]map[gopacket.Flow]bool)
)

// smc definitions
var (
	// smc variables
	smcOption      = smcrEyecatcher
	smcrEyecatcher = []byte{0xE2, 0xD4, 0xC3, 0xD9}
	smcdEyecatcher = []byte{0xE2, 0xD4, 0xC3, 0xC4}
)

const (
	// general
	smcSystemIDLen = 8

	// header/message lengths
	clcHeaderLen  = 8
	clcDeclineLen = 28

	// clc message types
	clcProposal = 0x01
	clcAccept   = 0x02
	clcConfirm  = 0x03
	clcDecline  = 0x04

	// decline diagnosis codes (linux)
	clcDeclineMem        = 0x01010000 /* insufficient memory resources */
	clcDeclineTimeout_CL = 0x02010000 /* timeout w4 QP confirm link */
	clcDeclineTimeout_AL = 0x02020000 /* timeout w4 QP add link */
	clcDeclineCnfErr     = 0x03000000 /* configuration error */
	clcDeclinePeerNoSMC  = 0x03010000 /* peer did not indicate SMC */
	clcDeclineIPSEC      = 0x03020000 /* IPsec usage */
	clcDeclineNoSMCDev   = 0x03030000 /* no SMC device found (R or D) */
	clcDeclineNoSMCDDev  = 0x03030001 /* no SMC-D device found */
	clcDeclineNoSMCRDev  = 0x03030002 /* no SMC-R device found */
	clcDeclineSMCDNoTalk = 0x03030003 /* SMC-D dev can't talk to peer */
	clcDeclineModeUnsupp = 0x03040000 /* smc modes do not match (R or D) */
	clcDeclineRMBE_EC    = 0x03050000 /* peer has eyecatcher in RMBE */
	clcDeclineOptUnsupp  = 0x03060000 /* fastopen sockopt not supported */
	clcDeclineDiffPrefix = 0x03070000 /* IP prefix / subnet mismatch */
	clcDeclineGetVLANErr = 0x03080000 /* err to get vlan id of ip device */
	clcDeclineISMVLANErr = 0x03090000 /* err to reg vlan id on ism dev */
	clcDeclineSyncErr    = 0x04000000 /* synchronization error */
	clcDeclinePeerDecl   = 0x05000000 /* peer declined during handshake */
	clcDeclineInterr     = 0x09990000 /* internal error */
	clcDeclineERR_RTok   = 0x09990001 /* rtoken handling failed */
	clcDeclineERR_RdyLnk = 0x09990002 /* ib ready link failed */
	clcDeclineERR_RegRMB = 0x09990003 /* reg rmb failed */
)

// CLC Decline Message
type clcDeclineMsg struct {
	hdr           *clcHeader
	senderPeerID  [smcSystemIDLen]byte /* sender peer_id */
	peerDiagnosis uint32               /* diagnosis information */
	reserved      [4]byte
	trailer       [4]byte /* eye catcher "SMCR" EBCDIC */
}

// convert CLC Decline Message to string
func (d *clcDeclineMsg) String() string {
	declineFmt := "Sender Peer ID: %s, Peer Diagnosis: %s"

	// parse peer diagnosis code
	var diag string
	switch d.peerDiagnosis {
	case clcDeclineMem:
		diag = "insufficient memory resources"
	case clcDeclineTimeout_CL:
		diag = "timeout w4 QP confirm link"
	case clcDeclineTimeout_AL:
		diag = "timeout w4 QP add link"
	case clcDeclineCnfErr:
		diag = "configuration error"
	case clcDeclinePeerNoSMC:
		diag = "peer did not indicate SMC"
	case clcDeclineIPSEC:
		diag = "IPsec usage"
	case clcDeclineNoSMCDev:
		diag = "no SMC device found (R or D)"
	case clcDeclineNoSMCDDev:
		diag = "no SMC-D device found"
	case clcDeclineNoSMCRDev:
		diag = "no SMC-R device found"
	case clcDeclineSMCDNoTalk:
		diag = "SMC-D dev can't talk to peer"
	case clcDeclineModeUnsupp:
		diag = "smc modes do not match (R or D)"
	case clcDeclineRMBE_EC:
		diag = "peer has eyecatcher in RMBE"
	case clcDeclineOptUnsupp:
		diag = "fastopen sockopt not supported"
	case clcDeclineDiffPrefix:
		diag = "IP prefix / subnet mismatch"
	case clcDeclineGetVLANErr:
		diag = "err to get vlan id of ip device"
	case clcDeclineISMVLANErr:
		diag = "err to reg vlan id on ism dev"
	case clcDeclineSyncErr:
		diag = "synchronization error"
	case clcDeclinePeerDecl:
		diag = "peer declined during handshake"
	case clcDeclineInterr:
		diag = "internal error"
	case clcDeclineERR_RTok:
		diag = "rtoken handling failed"
	case clcDeclineERR_RdyLnk:
		diag = "ib ready link failed"
	case clcDeclineERR_RegRMB:
		diag = "reg rmb failed"
	default:
		diag = "Unknown"
	}

	return fmt.Sprintf(declineFmt, d.senderPeerID, diag)
}

// CLC header
type clcHeader struct { /* header1 of clc messages */
	eyecatcher [4]byte
	typ        uint8 /* proposal / accept / confirm / decline */
	length     uint16

	// 1 byte bitfield containing version, flag, rsvd, path:
	version uint8 // (4 bits)
	flag    uint8 // (1 bit)
	rsvd    uint8 // (1 bit)
	path    uint8 // (2 bits)
}

// convert header fields to a string
func (c *clcHeader) String() string {
	headerFmt := "%s (eyecatcher: %s, length: %d, version: %d, " +
		"flag %d, rsvd: %d, path %d)"
	var eye string
	var typ string

	// type of eyecatcher
	if bytes.Compare(c.eyecatcher[:], smcrEyecatcher) == 0 {
		eye = "SMC-R"
	} else if bytes.Compare(c.eyecatcher[:], smcdEyecatcher) == 0 {
		eye = "SMC-R"
	} else {
		eye = "Unknown"
	}

	// message type
	switch c.typ {
	case clcProposal:
		typ = "Proposal"
	case clcAccept:
		typ = "Accept"
	case clcConfirm:
		typ = "Confirm"
	case clcDecline:
		typ = "Decline"
	default:
		typ = "Unknown"
	}

	// construct string
	return fmt.Sprintf(headerFmt, typ, eye, c.length, c.version, c.flag,
		c.rsvd, c.path)
}

// check if there is a SMC-R or SMC-D eyecatcher in the buffer
func hasEyecatcher(buf []byte) bool {
	if bytes.Compare(buf[0:4], smcrEyecatcher) == 0 {
		return true
	}
	if bytes.Compare(buf[0:4], smcdEyecatcher) == 0 {
		return true
	}
	return false
}

// parse CLC Decline in buffer
func parseCLCDecline(hdr *clcHeader, buf []byte) *clcDeclineMsg {
	decline := clcDeclineMsg{}
	decline.hdr = hdr

	// parse message content
	buf = buf[clcHeaderLen:]
	copy(decline.senderPeerID[:], buf[:smcSystemIDLen])
	buf = buf[smcSystemIDLen:]
	decline.peerDiagnosis = binary.BigEndian.Uint32(buf[:4])
	buf = buf[4:]
	copy(decline.reserved[:], buf[:4])
	buf = buf[4:]
	copy(decline.trailer[:], buf[:4])

	return &decline
}

// parse CLC header in buffer
func parseCLCHeader(buf []byte) *clcHeader {
	header := clcHeader{}

	// check eyecatcher first
	if !hasEyecatcher(buf) {
		return nil
	}

	copy(header.eyecatcher[:], buf[0:4])
	header.typ = buf[4]
	header.length = binary.BigEndian.Uint16(buf[5:7])

	// parse bitfield
	bitfield := buf[7]
	header.version = (bitfield & 0b11110000) >> 4
	header.flag = (bitfield & 0b00001000) >> 3
	header.rsvd = (bitfield & 0b00000100) >> 2
	header.path = (bitfield & 0b00000011)

	return &header
}

// smcStreamFactory implementing tcpassembly.StreamFactory
type smcStreamFactory struct{}

// smcStream for decoding of smc packets
type smcStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
}

// create new smc stream factory (-> implement tcpassembly.StreamFactory)
func (h *smcStreamFactory) New(
	net, transport gopacket.Flow) tcpassembly.Stream {
	sstream := &smcStream{
		net:       net,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
	}
	go sstream.run() // parse stream in goroutine

	// ReaderStream implements tcpassembly.Stream, so we can return a
	// pointer to it.
	return &sstream.r
}

// print CLC info of stream
func printCLC(s *smcStream, clc *clcHeader) {
	clcFmt := "%s:%s -> %s:%s: %s\n"

	fmt.Printf(clcFmt, s.net.Src(), s.transport.Src(), s.net.Dst(),
		s.transport.Dst(), clc)
}

// parse smc stream
func (s *smcStream) run() {
	buf := make([]byte, 2048)
	total := 0
	skip := 0
	var clc *clcHeader

	for {
		// read data into buffer and check EOF and errors
		n, err := s.r.Read(buf[total:])
		if err != nil {
			if err != io.EOF {
				log.Println("Error reading stream:", err)
			}
			break
		}
		total += n

		// wait for enough data for parsing CLC message
		if clc != nil && total >= skip {
			switch clc.typ {
			case clcConfirm:
				// handshake finished
				break
			case clcDecline:
				decline := parseCLCDecline(clc,
					buf[skip-clcDeclineLen:])
				fmt.Println("   ", decline)
				// handshake finished
				break
			}
		}

		// wait for enough data for parsing next CLC header
		if total-skip < clcHeaderLen {
			continue
		}

		// parse current CLC header
		clc = parseCLCHeader(buf[skip:])
		if clc == nil {
			break
		}

		// print current header
		printCLC(s, clc)

		// skip to next header if handshake still active
		skip += int(clc.length)
	}
	tcpreader.DiscardBytesToEOF(&s.r)
}

// check if SMC option is set in TCP header
func checkSMCOption(tcp *layers.TCP) bool {
	for _, opt := range tcp.Options {
		if opt.OptionType == 254 &&
			opt.OptionLength == 6 &&
			bytes.Compare(opt.OptionData, smcOption) == 0 {
			return true
		}
	}

	return false
}

// listen on network interface and parse packets
func listen() {
	pcapSnaplen := int32(1024)

	// open device
	pcapHandle, pcapErr := pcap.OpenLive(*pcapDevice, pcapSnaplen,
		*pcapPromisc, pcap.BlockForever)
	if pcapErr != nil {
		log.Fatal(pcapErr)
	}
	defer pcapHandle.Close()

	// Set up assembly
	streamFactory := &smcStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(pcapHandle,
		pcapHandle.LinkType())
	for packet := range packetSource.Packets() {
		// only handle tcp packets (with valid network layer)
		if packet.NetworkLayer() == nil ||
			packet.TransportLayer() == nil ||
			packet.TransportLayer().LayerType() !=
				layers.LayerTypeTCP {
			continue
		}
		tcp, ok := packet.TransportLayer().(*layers.TCP)
		if !ok {
			log.Fatal("Error parsing TCP packet")
		}

		// if smc option is set, try to parse tcp stream
		nflow := packet.NetworkLayer().NetworkFlow()
		tflow := packet.TransportLayer().TransportFlow()
		if checkSMCOption(tcp) || flows[nflow][tflow] {
			if flows[nflow] == nil {
				flows[nflow] = make(map[gopacket.Flow]bool)
			}
			flows[nflow][tflow] = true
			assembler.AssembleWithTimestamp(nflow, tcp,
				packet.Metadata().Timestamp)
		}
	}
}

// main
func main() {
	flag.Parse()
	listen()
}
