package messages

import "fmt"

// rmbeSize stores the SMC RMBE size
type rmbeSize uint8

// String converts rmbeSize to a string
func (s rmbeSize) String() string {
	size := 1 << (s + 14)
	return fmt.Sprintf("%d (%d)", s, size)
}

// clcAcceptConfirmMsg stores a CLC Accept/Confirm Message
type clcAcceptConfirmMsg struct {
	hdr  *CLCMessage
	smcr *clcSMCRAcceptConfirmMsg
	smcd *clcSMCDAcceptConfirmMsg
}

// String converts the CLC Accept/Confirm message to a string
func (ac *clcAcceptConfirmMsg) String() string {
	if ac == nil {
		return "n/a"
	}
	if ac.smcr != nil {
		return ac.smcr.String()
	}
	if ac.smcd != nil {
		return ac.smcd.String()
	}
	return "Unknown"
}

// Reserved converts the CLC Accept/Confirm message to a string including
// reserved message fields
func (ac *clcAcceptConfirmMsg) Reserved() string {
	if ac == nil {
		return "n/a"
	}
	if ac.smcr != nil {
		return ac.smcr.Reserved()
	}
	if ac.smcd != nil {
		return ac.smcd.Reserved()
	}
	return "Unknown"
}

// parseCLCAcceptConfirm parses the Accept/Confirm Message in buf
func parseCLCAcceptConfirm(hdr *CLCMessage, buf []byte) *clcAcceptConfirmMsg {
	ac := clcAcceptConfirmMsg{}
	ac.hdr = hdr

	if hdr.path == smcTypeR {
		ac.smcr = parseSMCRAcceptConfirm(hdr, buf)
	}
	if hdr.path == smcTypeD {
		ac.smcd = parseSMCDAcceptConfirm(hdr, buf)
	}

	return &ac
}
