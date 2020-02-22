package messages

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
)

const (
	clcProposalLen   = 52 // minimum length
	clcIPv6PrefixLen = 17
)

// SMC IPv6 Prefix
type ipv6Prefix struct {
	prefix    net.IP
	prefixLen uint8
}

func (p ipv6Prefix) String() string {
	return fmt.Sprintf("%s/%d", p.prefix, p.prefixLen)
}

// CLC Proposal Message
type clcProposalMsg struct {
	hdr          *CLCMessage
	senderPeerID peerID           /* unique system id */
	ibGID        net.IP           /* gid of ib_device port */
	ibMAC        net.HardwareAddr /* mac of ib_device port */
	ipAreaOffset uint16           /* offset to IP address info area */

	// Optional SMC-D info
	smcdGID  uint64 /* ISM GID of requestor */
	reserved [32]byte

	// IP/prefix info
	prefix          net.IP /* subnet mask (rather prefix) */
	prefixLen       uint8  /* number of significant bits in mask */
	reserved2       [2]byte
	ipv6PrefixesCnt uint8 /* number of IPv6 prefixes in prefix array */
	ipv6Prefixes    []ipv6Prefix
}

// convert CLC Proposal to string
func (p *clcProposalMsg) String() string {
	if p == nil {
		return "n/a"
	}

	// ipv6 prefixes
	ipv6Prefixes := ""
	for _, prefix := range p.ipv6Prefixes {
		ipv6Prefixes += fmt.Sprintf(", IPv6 Prefix: %s", prefix)
	}

	proposalFmt := "Peer ID: %s, SMC-R GID: %s, RoCE MAC: %s, " +
		"IP Area Offset: %d, SMC-D GID: %d, " +
		"IPv4 Prefix: %s/%d, IPv6 Prefix Count: %d%s"
	return fmt.Sprintf(proposalFmt, p.senderPeerID, p.ibGID, p.ibMAC,
		p.ipAreaOffset, p.smcdGID, p.prefix, p.prefixLen,
		p.ipv6PrefixesCnt, ipv6Prefixes)
}

func (p *clcProposalMsg) Reserved() string {
	if p == nil {
		return "n/a"
	}

	// ipv6 prefixes
	ipv6Prefixes := ""
	for _, prefix := range p.ipv6Prefixes {
		ipv6Prefixes += fmt.Sprintf(", IPv6 Prefix: %s", prefix)
	}

	proposalFmt := "Peer ID: %s, SMC-R GID: %s, RoCE MAC: %s, " +
		"IP Area Offset: %d, SMC-D GID: %d, Reserved: %#x " +
		"IPv4 Prefix: %s/%d, Reserved: %#x, " +
		"IPv6 Prefix Count: %d%s"
	return fmt.Sprintf(proposalFmt, p.senderPeerID, p.ibGID,
		p.ibMAC, p.ipAreaOffset, p.smcdGID, p.reserved,
		p.prefix, p.prefixLen, p.reserved2, p.ipv6PrefixesCnt,
		ipv6Prefixes)
}

// parse CLC Proposal in buffer
func parseCLCProposal(hdr *CLCMessage, buf []byte) *clcProposalMsg {
	proposal := clcProposalMsg{}
	proposal.hdr = hdr

	// check if message is long enough
	if hdr.Length < clcProposalLen {
		log.Println("Error parsing CLC Proposal: message too short")
		errDump(buf[:hdr.Length])
		return nil
	}

	// skip clc header
	skip := CLCHeaderLen

	// sender peer ID
	copy(proposal.senderPeerID[:], buf[skip:skip+peerIDLen])
	skip += peerIDLen

	// ib GID is an IPv6 address
	proposal.ibGID = make(net.IP, net.IPv6len)
	copy(proposal.ibGID[:], buf[skip:skip+net.IPv6len])
	skip += net.IPv6len

	// ib MAC is a 6 byte MAC address
	proposal.ibMAC = make(net.HardwareAddr, 6)
	copy(proposal.ibMAC[:], buf[skip:skip+6])
	skip += 6

	// offset to ip area
	proposal.ipAreaOffset = binary.BigEndian.Uint16(buf[skip : skip+2])
	skip += 2

	// Optional SMC-D info
	if proposal.ipAreaOffset == 40 {
		// smcd GID
		proposal.smcdGID = binary.BigEndian.Uint64(buf[skip : skip+8])
		skip += 8

		// reserved
		copy(proposal.reserved[:], buf[skip:skip+32])
		skip += 32
	} else {
		skip += int(proposal.ipAreaOffset)
	}

	// make sure we do not read outside the message
	if int(hdr.Length)-skip < net.IPv4len+1+2+1+clcTrailerLen {
		log.Println("Error parsing CLC Proposal: " +
			"IP Area Offset too big")
		errDump(buf[:hdr.Length])
		return nil
	}

	// IP/prefix is an IPv4 address
	proposal.prefix = make(net.IP, net.IPv4len)
	copy(proposal.prefix[:], buf[skip:skip+net.IPv4len])
	skip += net.IPv4len

	// prefix length
	proposal.prefixLen = uint8(buf[skip])
	skip++

	// reserved
	copy(proposal.reserved2[:], buf[skip:skip+2])
	skip += 2

	// ipv6 prefix count
	proposal.ipv6PrefixesCnt = uint8(buf[skip])

	// parse ipv6 prefixes
	for i := uint8(0); i < proposal.ipv6PrefixesCnt; i++ {
		// skip prefix count or last prefix length
		skip++

		// make sure we are still inside the clc message
		if int(hdr.Length)-skip < clcIPv6PrefixLen+clcTrailerLen {
			log.Println("Error parsing CLC Proposal: " +
				"IPv6 prefix count too big")
			errDump(buf[:hdr.Length])
			break
		}
		// create new ipv6 prefix entry
		ip6prefix := ipv6Prefix{}

		// parse prefix and fill prefix entry
		ip6prefix.prefix = make(net.IP, net.IPv6len)
		copy(ip6prefix.prefix[:], buf[skip:skip+net.IPv6len])
		skip += net.IPv6len

		// parse prefix length and fill prefix entry
		ip6prefix.prefixLen = uint8(buf[skip])

		// add to ipv6 prefixes
		proposal.ipv6Prefixes = append(proposal.ipv6Prefixes,
			ip6prefix)
	}

	return &proposal
}
