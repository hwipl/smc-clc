package messages

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
)

const (
	clcSMCRAcceptConfirmLen = 68
)

// qpMTU stores a SMC QP MTU
type qpMTU uint8

// String converts qpMTU to a string
func (m qpMTU) String() string {
	var mtu string

	switch m {
	case 1:
		mtu = "256"

	case 2:
		mtu = "512"

	case 3:
		mtu = "1024"

	case 4:
		mtu = "2048"

	case 5:
		mtu = "4096"
	default:
		mtu = "reserved"
	}

	return fmt.Sprintf("%d (%s)", m, mtu)
}

// clcSMCRAcceptConfirmMsg stores a CLC SMC-R Accept/Confirm Message
type clcSMCRAcceptConfirmMsg struct {
	hdr            *CLCMessage
	senderPeerID   peerID           /* unique system id */
	ibGID          net.IP           /* gid of ib_device port */
	ibMAC          net.HardwareAddr /* mac of ib_device port */
	qpn            int              /* QP number */
	rmbRkey        uint32           /* RMB rkey */
	rmbeIdx        uint8            /* Index of RMBE in RMB */
	rmbeAlertToken uint32           /* unique connection id */
	rmbeSize       rmbeSize         /* 4 bits buf size (compressed) */
	qpMtu          qpMTU            /* 4 bits QP mtu */
	reserved       byte
	rmbDmaAddr     uint64 /* RMB virtual address */
	reserved2      byte
	psn            int /* packet sequence number */
}

// String converts the CLC SMC-R Accept/Confirm to a string
func (ac *clcSMCRAcceptConfirmMsg) String() string {
	if ac == nil {
		return "n/a"
	}

	acFmt := "Peer ID: %s, SMC-R GID: %s, RoCE MAC: %s, " +
		"QP Number: %d, RMB RKey: %d, RMBE Index: %d, " +
		"RMBE Alert Token: %d, RMBE Size: %s, QP MTU: %s, " +
		"RMB Virtual Address: %#x, Packet Sequence Number: %d"
	return fmt.Sprintf(acFmt, ac.senderPeerID, ac.ibGID, ac.ibMAC, ac.qpn,
		ac.rmbRkey, ac.rmbeIdx, ac.rmbeAlertToken, ac.rmbeSize,
		ac.qpMtu, ac.rmbDmaAddr, ac.psn)
}

// Reserved converts the CLC SMC-R Accept/Confirm to a string including
// reserved message fields
func (ac *clcSMCRAcceptConfirmMsg) Reserved() string {
	if ac == nil {
		return "n/a"
	}

	acFmt := "Peer ID: %s, SMC-R GID: %s, RoCE MAC: %s, " +
		"QP Number: %d, RMB RKey: %d, RMBE Index: %d, " +
		"RMBE Alert Token: %d, RMBE Size: %s, QP MTU: %s, " +
		"Reserved: %#x, RMB Virtual Address: %#x, " +
		"Reserved: %#x, Packet Sequence Number: %d"
	return fmt.Sprintf(acFmt, ac.senderPeerID, ac.ibGID, ac.ibMAC,
		ac.qpn, ac.rmbRkey, ac.rmbeIdx, ac.rmbeAlertToken,
		ac.rmbeSize, ac.qpMtu, ac.reserved, ac.rmbDmaAddr,
		ac.reserved2, ac.psn)
}

// parseSMCRAcceptConfirm parses the SMC-R Accept/Confirm message in buf
func parseSMCRAcceptConfirm(
	hdr *CLCMessage, buf []byte) *clcSMCRAcceptConfirmMsg {
	ac := clcSMCRAcceptConfirmMsg{}
	ac.hdr = hdr

	// check if message is long enough
	if hdr.Length < clcSMCRAcceptConfirmLen {
		err := "Error parsing CLC Accept: message too short"
		if hdr.typ == clcConfirm {
			err = "Error parsing CLC Confirm: message too short"
		}
		log.Println(err)
		errDump(buf[:hdr.Length])
		return nil
	}

	// skip clc header
	buf = buf[CLCHeaderLen:]

	// sender peer ID
	copy(ac.senderPeerID[:], buf[:peerIDLen])
	buf = buf[peerIDLen:]

	// ib GID is an IPv6 Address
	ac.ibGID = make(net.IP, net.IPv6len)
	copy(ac.ibGID[:], buf[:net.IPv6len])
	buf = buf[net.IPv6len:]

	// ib MAC is a 6 byte MAC address
	ac.ibMAC = make(net.HardwareAddr, 6)
	copy(ac.ibMAC[:], buf[:6])
	buf = buf[6:]

	// QP number is 3 bytes
	ac.qpn = int(buf[0]) << 16
	ac.qpn |= int(buf[1]) << 8
	ac.qpn |= int(buf[2])
	buf = buf[3:]

	// rmb Rkey
	ac.rmbRkey = binary.BigEndian.Uint32(buf[:4])
	buf = buf[4:]

	// rmbe Idx
	ac.rmbeIdx = uint8(buf[0])
	buf = buf[1:]

	// rmbe alert token
	ac.rmbeAlertToken = binary.BigEndian.Uint32(buf[:4])
	buf = buf[4:]

	// 1 byte bitfield: rmbe size (4 bits) and qp mtu (4 bits)
	ac.rmbeSize = rmbeSize((uint8(buf[0]) & 0b11110000) >> 4)
	ac.qpMtu = qpMTU(uint8(buf[0]) & 0b00001111)
	buf = buf[1:]

	// reserved
	ac.reserved = buf[0]
	buf = buf[1:]

	// rmb DMA addr
	ac.rmbDmaAddr = binary.BigEndian.Uint64(buf[:8])
	buf = buf[8:]

	// reserved
	ac.reserved2 = buf[0]
	buf = buf[1:]

	// Packet Sequence Number is 3 bytes
	ac.psn = int(buf[0]) << 16
	ac.psn |= int(buf[1]) << 8
	ac.psn |= int(buf[2])
	buf = buf[3:]

	return &ac
}
