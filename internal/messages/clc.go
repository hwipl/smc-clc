package messages

import (
	"encoding/binary"
	"log"
)

const (
	// CLCMessageMaxSize is the maximum allowed CLC message size in bytes
	// (for sanity checks)
	CLCMessageMaxSize = 1024
)

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
