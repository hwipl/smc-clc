package messages

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net"
)

const (
	// CLCMessageMaxSize is the maximum allowed CLC message size in bytes
	// (for sanity checks)
	CLCMessageMaxSize = 1024

	// smc type/path
	smcTypeR = 0 // SMC-R only
	smcTypeD = 1 // SMC-D only
	smcTypeB = 3 // SMC-R and SMC-D

	// CLCHeaderLen is the length of the clc header in bytes
	CLCHeaderLen = 8

	// peerIDLen is the length of the peer ID in bytes
	peerIDLen = 8

	// clc message types
	clcProposal = 0x01
	clcAccept   = 0x02
	clcConfirm  = 0x03
	clcDecline  = 0x04
)

// message is a type for all clc messages
type message interface {
	String() string
	Reserved() string
}

// path stores an SMC path
type path uint8

// String converts the path to a string
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

// peerID stores a SMC peer ID
type peerID [peerIDLen]byte

// String converts the peer ID to a string
func (p peerID) String() string {
	instance := binary.BigEndian.Uint16(p[:2])
	roceMAC := net.HardwareAddr(p[2:8])
	return fmt.Sprintf("%d@%s", instance, roceMAC)
}

// CLCMessage stores a clc message
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

	// type dependent message content
	message message

	// trailer
	trailer eyecatcher

	// raw bytes buffer of the message
	raw []byte
}

// Parse parses the CLC message in buf
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
		c.message = parseCLCProposal(c, buf)
	case clcAccept:
		c.message = parseCLCAcceptConfirm(c, buf)
	case clcConfirm:
		c.message = parseCLCAcceptConfirm(c, buf)
	case clcDecline:
		c.message = parseCLCDecline(c, buf)
	}

	// save buffer
	c.raw = buf
}

// typeString() converts the message type to a string
func (c *CLCMessage) typeString() string {
	switch c.typ {
	case clcProposal:
		return "Proposal"
	case clcAccept:
		return "Accept"
	case clcConfirm:
		return "Confirm"
	case clcDecline:
		return "Decline"
	default:
		return "Unknown"
	}
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

// String converts the clc header fields to a string
func (c *CLCMessage) String() string {
	if c == nil {
		return "n/a"
	}

	// construct string
	typ := c.typeString()
	flg := c.flagString()
	msg := "n/a"
	if c.message != nil {
		msg = c.message.String()
	}

	headerFmt := "%s: Eyecatcher: %s, Type: %d (%s), Length: %d, " +
		"Version: %d, %s, Path: %s, %s, Trailer: %s"
	return fmt.Sprintf(headerFmt, typ, c.eyecatcher, c.typ, typ, c.Length,
		c.version, flg, c.path, msg, c.trailer)
}

// Reserved converts the clc header fields to a string including reserved
// message fields
func (c *CLCMessage) Reserved() string {
	if c == nil {
		return "n/a"
	}

	// construct string
	typ := c.typeString()
	flg := c.flagString()
	msg := "n/a"
	if c.message != nil {
		msg = c.message.Reserved()
	}
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

// ParseCLCHeader parses the CLC header in buf
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
