package messages

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net"
)

const (
	// maximum allowed CLC message size (for sanity checks)
	CLCMessageMaxSize = 1024

	// smc type/path
	smcTypeR = 0 /* SMC-R only */
	smcTypeD = 1 /* SMC-D only */
	smcTypeB = 3 /* SMC-R and SMC-D */

	// clc header
	CLCHeaderLen = 8

	// peer ID
	peerIDLen = 8

	// clc message types
	clcProposal = 0x01
	clcAccept   = 0x02
	clcConfirm  = 0x03
	clcDecline  = 0x04
)

// SMC path
type path uint8

func (p path) String() string {
	switch p {
	case smcTypeR:
		return "SMC-R"
	case smcTypeD:
		return "SMC-D"
	case smcTypeB:
		return "SMC-R + SMC-D"
	default:
		return "unknown"
	}
}

// SMC peer ID
type peerID [peerIDLen]byte

func (p peerID) String() string {
	instance := binary.BigEndian.Uint16(p[:2])
	roceMAC := net.HardwareAddr(p[2:8])
	return fmt.Sprintf("%d@%s", instance, roceMAC)
}

// CLC message
type CLCMessage struct {
	// eyecatcher
	eyecatcher eyecatcher

	// type of message: proposal, accept, confirm, decline
	typ uint8

	// total length of message
	Length uint16

	// 1 byte bitfield containing version, flag, reserved, path:
	version  uint8 // (4 bits)
	flag     uint8 // (1 bit)
	reserved byte  // (1 bit)
	path     path  // (2 bits)

	// type depenent message content
	proposal *clcProposalMsg
	accept   *clcAcceptConfirmMsg
	confirm  *clcAcceptConfirmMsg
	decline  *clcDeclineMsg

	// trailer
	trailer eyecatcher

	// raw bytes buffer of the message
	raw []byte
}

// parse CLC message
func (c *CLCMessage) Parse(buf []byte) {
	// trailer
	copy(c.trailer[:], buf[c.Length-clcTrailerLen:])
	if !hasEyecatcher(c.trailer[:]) {
		log.Println("Error parsing CLC message: invalid trailer")
		errDump(buf[:c.Length])
		return
	}

	// parse type dependent message content
	switch c.typ {
	case clcProposal:
		c.proposal = parseCLCProposal(c, buf)
	case clcAccept:
		c.accept = parseCLCAcceptConfirm(c, buf)
	case clcConfirm:
		c.confirm = parseCLCAcceptConfirm(c, buf)
	case clcDecline:
		c.decline = parseCLCDecline(c, buf)
	}

	// save buffer
	c.raw = buf
}

// flagString() converts the flag bit in the message according the message type
func (c *CLCMessage) flagString() string {
	switch c.typ {
	case clcProposal:
		return fmt.Sprintf("Flag: %d", c.flag)
	case clcAccept:
		return fmt.Sprintf("First Contact: %d", c.flag)
	case clcConfirm:
		return fmt.Sprintf("Flag: %d", c.flag)
	case clcDecline:
		return fmt.Sprintf("Out of Sync: %d", c.flag)
	default:
		return fmt.Sprintf("Flag: %d", c.flag)
	}
}

// convert header fields to a string
func (c *CLCMessage) String() string {
	var typ string
	var msg string

	if c == nil {
		return "n/a"
	}

	// message type
	switch c.typ {
	case clcProposal:
		typ = "Proposal"
		msg = c.proposal.String()
	case clcAccept:
		typ = "Accept"
		msg = c.accept.String()
	case clcConfirm:
		typ = "Confirm"
		msg = c.confirm.String()
	case clcDecline:
		typ = "Decline"
		msg = c.decline.String()
	default:
		typ = "Unknown"
		msg = "n/a"
	}

	// construct string
	flg := c.flagString()
	headerFmt := "%s: Eyecatcher: %s, Type: %d (%s), Length: %d, " +
		"Version: %d, %s, Path: %s, %s, Trailer: %s"
	return fmt.Sprintf(headerFmt, typ, c.eyecatcher, c.typ, typ, c.Length,
		c.version, flg, c.path, msg, c.trailer)
}

func (c *CLCMessage) Reserved() string {
	var typ string
	var msg string

	if c == nil {
		return "n/a"
	}

	// message type
	switch c.typ {
	case clcProposal:
		typ = "Proposal"
		msg = c.proposal.Reserved()
	case clcAccept:
		typ = "Accept"
		msg = c.accept.Reserved()
	case clcConfirm:
		typ = "Confirm"
		msg = c.confirm.Reserved()
	case clcDecline:
		typ = "Decline"
		msg = c.decline.Reserved()
	default:
		typ = "Unknown"
		msg = "n/a"
	}

	// construct string
	flg := c.flagString()
	headerFmt := "%s: Eyecatcher: %s, Type: %d (%s), Length: %d, " +
		"Version: %d, %s, Reserved: %#x, Path: %s, %s, " +
		"Trailer: %s"
	return fmt.Sprintf(headerFmt, typ, c.eyecatcher, c.typ, typ,
		c.Length, c.version, flg, c.reserved, c.path, msg,
		c.trailer)
}

// Dump returns the raw bytes buffer of the message as hex dump string
func (c *CLCMessage) Dump() string {
	return hex.Dump(c.raw)
}

// parse CLC header in buffer
func ParseCLCHeader(buf []byte) *CLCMessage {
	header := CLCMessage{}

	// check eyecatcher first
	if !hasEyecatcher(buf) {
		return nil
	}

	// eyecatcher
	copy(header.eyecatcher[:], buf[:clcEyecatcherLen])

	// type
	header.typ = buf[4]

	// length
	header.Length = binary.BigEndian.Uint16(buf[5:7])

	// check if message is not too big
	if header.Length > CLCMessageMaxSize {
		log.Println("Error parsing CLC header: message too big")
		errDump(buf[:CLCHeaderLen])
		return nil
	}

	// 1 byte bitfield: version, flag, reserved, path
	bitfield := buf[7]
	header.version = (bitfield & 0b11110000) >> 4
	header.flag = (bitfield & 0b00001000) >> 3
	header.reserved = (bitfield & 0b00000100) >> 2
	header.path = path(bitfield & 0b00000011)

	return &header
}
