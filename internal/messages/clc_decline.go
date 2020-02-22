package messages

import (
	"encoding/binary"
	"fmt"
	"log"
)

const (
	// clc decline message
	clcDeclineLen = 28

	// decline diagnosis codes (linux)
	clcDeclineMem        = 0x01010000 /* insufficient memory resources */
	clcDeclineTimeoutCL  = 0x02010000 /* timeout w4 QP confirm link */
	clcDeclineTimeoutAL  = 0x02020000 /* timeout w4 QP add link */
	clcDeclineCnfErr     = 0x03000000 /* configuration error */
	clcDeclinePeerNoSMC  = 0x03010000 /* peer did not indicate SMC */
	clcDeclineIPSEC      = 0x03020000 /* IPsec usage */
	clcDeclineNoSMCDev   = 0x03030000 /* no SMC device found (R or D) */
	clcDeclineNoSMCDDev  = 0x03030001 /* no SMC-D device found */
	clcDeclineNoSMCRDev  = 0x03030002 /* no SMC-R device found */
	clcDeclineSMCDNoTalk = 0x03030003 /* SMC-D dev can't talk to peer */
	clcDeclineModeUnsupp = 0x03040000 /* smc modes do not match (R or D) */
	clcDeclineRMBEEyeC   = 0x03050000 /* peer has eyecatcher in RMBE */
	clcDeclineOptUnsupp  = 0x03060000 /* fastopen sockopt not supported */
	clcDeclineDiffPrefix = 0x03070000 /* IP prefix / subnet mismatch */
	clcDeclineGetVLANErr = 0x03080000 /* err to get vlan id of ip device */
	clcDeclineISMVLANErr = 0x03090000 /* err to reg vlan id on ism dev */
	clcDeclineSyncErr    = 0x04000000 /* synchronization error */
	clcDeclinePeerDecl   = 0x05000000 /* peer declined during handshake */
	clcDeclineInterr     = 0x09990000 /* internal error */
	clcDeclineErrRTok    = 0x09990001 /* rtoken handling failed */
	clcDeclineErrRdyLnk  = 0x09990002 /* ib ready link failed */
	clcDeclineErrRegRMB  = 0x09990003 /* reg rmb failed */
)

type peerDiagnosis uint32

func (p peerDiagnosis) String() string {
	// parse peer diagnosis code
	var diag string
	switch p {
	case clcDeclineMem:
		diag = "insufficient memory resources"
	case clcDeclineTimeoutCL:
		diag = "timeout w4 QP confirm link"
	case clcDeclineTimeoutAL:
		diag = "timeout w4 QP add link"
	case clcDeclineCnfErr:
		diag = "configuration error"
	case clcDeclinePeerNoSMC:
		diag = "peer did not indicate SMC"
	case clcDeclineIPSEC:
		diag = "IPsec usage"
	case clcDeclineNoSMCDev:
		diag = "no SMC device found (R or D)"
	case clcDeclineNoSMCDDev:
		diag = "no SMC-D device found"
	case clcDeclineNoSMCRDev:
		diag = "no SMC-R device found"
	case clcDeclineSMCDNoTalk:
		diag = "SMC-D dev can't talk to peer"
	case clcDeclineModeUnsupp:
		diag = "smc modes do not match (R or D)"
	case clcDeclineRMBEEyeC:
		diag = "peer has eyecatcher in RMBE"
	case clcDeclineOptUnsupp:
		diag = "fastopen sockopt not supported"
	case clcDeclineDiffPrefix:
		diag = "IP prefix / subnet mismatch"
	case clcDeclineGetVLANErr:
		diag = "err to get vlan id of ip device"
	case clcDeclineISMVLANErr:
		diag = "err to reg vlan id on ism dev"
	case clcDeclineSyncErr:
		diag = "synchronization error"
	case clcDeclinePeerDecl:
		diag = "peer declined during handshake"
	case clcDeclineInterr:
		diag = "internal error"
	case clcDeclineErrRTok:
		diag = "rtoken handling failed"
	case clcDeclineErrRdyLnk:
		diag = "ib ready link failed"
	case clcDeclineErrRegRMB:
		diag = "reg rmb failed"
	default:
		diag = "Unknown"
	}
	return fmt.Sprintf("%#x (%s)", uint32(p), diag)
}

// CLC Decline Message
type clcDeclineMsg struct {
	hdr           *CLCMessage
	senderPeerID  peerID        /* sender peer_id */
	peerDiagnosis peerDiagnosis /* diagnosis information */
	reserved      [4]byte
}

// convert CLC Decline Message to string
func (d *clcDeclineMsg) String() string {
	if d == nil {
		return "n/a"
	}

	declineFmt := "Peer ID: %s, Peer Diagnosis: %s"
	return fmt.Sprintf(declineFmt, d.senderPeerID, d.peerDiagnosis)
}

func (d *clcDeclineMsg) Reserved() string {
	if d == nil {
		return "n/a"
	}

	declineFmt := "Peer ID: %s, Peer Diagnosis: %s, Reserved: %#x"
	return fmt.Sprintf(declineFmt, d.senderPeerID, d.peerDiagnosis,
		d.reserved)
}

// parse CLC Decline in buffer
func parseCLCDecline(hdr *CLCMessage, buf []byte) *clcDeclineMsg {
	decline := clcDeclineMsg{}
	decline.hdr = hdr

	// check if message is long enough
	if hdr.Length < clcDeclineLen {
		log.Println("Error parsing CLC Decline: message too short")
		errDump(buf[:hdr.Length])
		return nil
	}

	// skip clc header
	buf = buf[CLCHeaderLen:]

	// sender peer ID
	copy(decline.senderPeerID[:], buf[:peerIDLen])
	buf = buf[peerIDLen:]

	// peer diagnosis
	decline.peerDiagnosis = peerDiagnosis(binary.BigEndian.Uint32(buf[:4]))
	buf = buf[4:]

	// reserved
	copy(decline.reserved[:], buf[:4])
	buf = buf[4:]

	return &decline
}