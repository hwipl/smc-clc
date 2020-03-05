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
type Message interface {
	Parse([]byte)
	String() string
	Reserved() string
	Dump() string
	GetLength() uint16
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

	// trailer
	trailer eyecatcher

	// raw bytes buffer of the message
	raw []byte
}

// Parse parses the CLC message in buf
func (c *CLCMessage) Parse(buf []byte) {
	// eyecatcher
	copy(c.eyecatcher[:], buf[:clcEyecatcherLen])

	// type
	c.typ = buf[4]

	// length
	c.Length = binary.BigEndian.Uint16(buf[5:7])

	// 1 byte bitfield: version, flag, reserved, path
	bitfield := buf[7]
	c.version = (bitfield & 0b11110000) >> 4
	c.flag = (bitfield & 0b00001000) >> 3
	c.reserved = (bitfield & 0b00000100) >> 2
	c.path = path(bitfield & 0b00000011)

	// trailer
	copy(c.trailer[:], buf[c.Length-clcTrailerLen:])
	if !hasEyecatcher(c.trailer[:]) {
		log.Println("Error parsing CLC message: invalid trailer")
		errDump(buf[:c.Length])
		return
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

// GetLength returns the length of the clc message in bytes
func (c *CLCMessage) GetLength() uint16 {
	return c.Length
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

// headerString converts the message header to a string
func (c *CLCMessage) headerString() string {
	typ := c.typeString()
	flg := c.flagString()
	headerFmt := "%s: Eyecatcher: %s, Type: %d (%s), Length: %d, " +
		"Version: %d, %s, Path: %s"
	return fmt.Sprintf(headerFmt, typ, c.eyecatcher, c.typ, typ, c.Length,
		c.version, flg, c.path)
}

// trailerString converts the message trailer to a string
func (c *CLCMessage) trailerString() string {
	trailerFmt := "Trailer: %s"
	return fmt.Sprintf(trailerFmt, c.trailer)
}

// headerReserved converts the message header fields to a string including
// reserved message fields
func (c *CLCMessage) headerReserved() string {
	// construct string
	typ := c.typeString()
	flg := c.flagString()

	headerFmt := "%s: Eyecatcher: %s, Type: %d (%s), Length: %d, " +
		"Version: %d, %s, Reserved: %#x, Path: %s"
	return fmt.Sprintf(headerFmt, typ, c.eyecatcher, c.typ, typ,
		c.Length, c.version, flg, c.reserved, c.path)
}

// Dump returns the raw bytes buffer of the message as hex dump string
func (c *CLCMessage) Dump() string {
	return hex.Dump(c.raw)
}

// NewMessage checks buf for a clc message and returns an empty message of
// respective type and its length in bytes. Parse the new message before
// actually using it
func NewMessage(buf []byte) (Message, uint16) {
	// check eyecatcher first
	if !hasEyecatcher(buf) {
		return nil, 0
	}

	// make sure message is not too big
	length := binary.BigEndian.Uint16(buf[5:7])
	if length > CLCMessageMaxSize {
		log.Println("Error parsing CLC header: message too big")
		errDump(buf[:CLCHeaderLen])
		return nil, 0
	}

	// return new (empty) message of correct type
	typ := buf[4]
	switch typ {
	case clcProposal:
		return &clcProposalMsg{}, length
	case clcAccept, clcConfirm:
		// check path to determine if it's smc-d or smc-d
		path := path(buf[7] & 0b00000011)
		switch path {
		case smcTypeR:
			return &clcSMCRAcceptConfirmMsg{}, length
		case smcTypeD:
			return &clcSMCDAcceptConfirmMsg{}, length
		}
	case clcDecline:
		return &clcDeclineMsg{}, length
	}

	return nil, 0
}
