package messages

import "fmt"

// SMC RMBE size
type rmbeSize uint8

func (s rmbeSize) String() string {
	size := 1 << (s + 14)
	return fmt.Sprintf("%d (%d)", s, size)
}

// CLC Accept/Confirm Message
type clcAcceptConfirmMsg struct {
	hdr  *CLCMessage
	smcr *clcSMCRAcceptConfirmMsg
	smcd *clcSMCDAcceptConfirmMsg
}

// convert CLC Accept/Confirm to string
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

// parse Accept/Confirm Message
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
