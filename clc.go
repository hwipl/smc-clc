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
	clcHeaderLen = 8

	// clc message types
	clcProposal = 0x01
	clcAccept   = 0x02
	clcConfirm  = 0x03
	clcDecline  = 0x04
)

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
	headerFmt := "Eyecatcher: %s, type: %s, length: %d, version: %d, " +
		"flag %d, rsvd: %d, path %d\n"
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
	return fmt.Sprintf(headerFmt, eye, typ, c.length, c.version, c.flag,
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

// parse smc stream
func (s *smcStream) run() {
	buf := make([]byte, 2048)
	total := 0
	var smc *clcHeader

	for {
		n, err := s.r.Read(buf[total:])
		total += n
		if err == io.EOF {
			break
		} else if err != nil {
			log.Println("Error reading stream:", err)
		} else {
			if total < clcHeaderLen {
				continue
			}
			smc = parseCLCHeader(buf)
			break
		}
	}
	if smc != nil {
		fmt.Println("SMC flow:           ", s.net, s.transport)
		fmt.Println("With CLC Header:    ", smc)
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
