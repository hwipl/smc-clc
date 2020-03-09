package messages

import (
	"encoding/binary"
	"fmt"
	"log"
)

const (
	clcSMCDAcceptConfirmLen = 48
)

// clcSMCDAcceptConfirmMsg stores a CLC SMC-D Accept/Confirm Message
type clcSMCDAcceptConfirmMsg struct {
	CLCMessage
	smcdGID   uint64   // Sender GID
	smcdToken uint64   // DMB token
	dmbeIdx   uint8    // DMBE index
	dmbeSize  rmbeSize // 4 bits buf size (compressed)
	reserved  byte     // 4 bits reserved
	reserved2 [2]byte
	linkid    uint32 // Link identifier
	reserved3 [12]byte
}

// String converts the CLC SMC-D Accept/Confirm to a string
func (ac *clcSMCDAcceptConfirmMsg) String() string {
	if ac == nil {
		return "n/a"
	}

	acFmt := "%s, SMC-D GID: %d, SMC-D Token: %d, DMBE Index: %d, " +
		"DMBE Size: %s, Link ID: %d, Trailer: %s"
	return fmt.Sprintf(acFmt, ac.headerString(), ac.smcdGID, ac.smcdToken,
		ac.dmbeIdx, ac.dmbeSize, ac.linkid, ac.trailer)
}

// Reserved converts the CLC SMC-D Accept/Confirm to a string including
// reserved message fields
func (ac *clcSMCDAcceptConfirmMsg) Reserved() string {
	if ac == nil {
		return "n/a"
	}

	acFmt := "%s, SMC-D GID: %d, SMC-D Token: %d, DMBE Index: %d, " +
		"DMBE Size: %s, Reserved: %#x, Reserved: %#x, " +
		"Link ID: %d, Reserved: %#x, Trailer: %s"
	return fmt.Sprintf(acFmt, ac.headerReserved(), ac.smcdGID,
		ac.smcdToken, ac.dmbeIdx, ac.dmbeSize, ac.reserved,
		ac.reserved2, ac.linkid, ac.reserved3, ac.trailer)
}

// Parse parses the SMC-D Accept/Confirm Message in buf
func (ac *clcSMCDAcceptConfirmMsg) Parse(buf []byte) {
	// parse clc header
	ac.CLCMessage.Parse(buf)

	// check if message is long enough
	if ac.Length < clcSMCDAcceptConfirmLen {
		err := "Error parsing CLC Accept: message too short"
		if ac.typ == clcConfirm {
			err = "Error parsing CLC Confirm: message too short"
		}
		log.Println(err)
		errDump(buf[:ac.Length])
		return
	}

	// skip clc header
	buf = buf[CLCHeaderLen:]

	// smcd GID
	ac.smcdGID = binary.BigEndian.Uint64(buf[:8])
	buf = buf[8:]

	// smcd Token
	ac.smcdToken = binary.BigEndian.Uint64(buf[:8])
	buf = buf[8:]

	// dmbe index
	ac.dmbeIdx = uint8(buf[0])
	buf = buf[1:]

	// 1 byte bitfield: dmbe size (4 bits), reserved (4 bits)
	ac.dmbeSize = rmbeSize((uint8(buf[0]) & 0b11110000) >> 4)
	ac.reserved = buf[0] & 0b00001111
	buf = buf[1:]

	// reserved
	copy(ac.reserved2[:], buf[:2])
	buf = buf[2:]

	// link id
	ac.linkid = binary.BigEndian.Uint32(buf[:4])
	buf = buf[4:]

	// reserved
	copy(ac.reserved3[:], buf[:12])
	buf = buf[12:]
}
