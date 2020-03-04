package messages

import "fmt"

// rmbeSize stores the SMC RMBE size
type rmbeSize uint8

// String converts rmbeSize to a string
func (s rmbeSize) String() string {
	size := 1 << (s + 14)
	return fmt.Sprintf("%d (%d)", s, size)
}

// parseCLCAcceptConfirm parses the Accept/Confirm Message in buf
func parseCLCAcceptConfirm(hdr *CLCMessage, buf []byte) Message {
	if hdr.path == smcTypeR {
		return parseSMCRAcceptConfirm(hdr, buf)
	}
	if hdr.path == smcTypeD {
		return parseSMCDAcceptConfirm(hdr, buf)
	}
	return nil
}
