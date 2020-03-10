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
	// header
	header

	// trailer
	trailer trailer

	// raw bytes buffer of the message
	raw []byte
}

// Parse parses the CLC message in buf
func (c *CLCMessage) Parse(buf []byte) {
	// header
	c.header.Parse(buf)

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
