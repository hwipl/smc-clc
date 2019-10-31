package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

var (
	// pcap variables
	pcapDevice  = flag.String("i", "eth0", "the interface to listen on")
	pcapPromisc = flag.Bool("promisc", true, "promiscuous mode")

	// display variables
	showReserved = flag.Bool("reserved", false,
		"print reserved values in messages")
	showTimestamps = flag.Bool("timestamps", true, "print timestamps")

	// flow table
	flows flowTable
)

// smc definitions
var (
	// smc variables
	smcOption      = smcrEyecatcher
	smcrEyecatcher = []byte{0xE2, 0xD4, 0xC3, 0xD9}
	smcdEyecatcher = []byte{0xE2, 0xD4, 0xC3, 0xC4}
)

const (
	// general
	peerIDLen = 8
	smcTypeR  = 0 /* SMC-R only */
	smcTypeD  = 1 /* SMC-D only */
	smcTypeB  = 3 /* SMC-R and SMC-D */

	// header/message lengths
	clcHeaderLen  = 8
	clcDeclineLen = 28

	// clc message types
	clcProposal = 0x01
	clcAccept   = 0x02
	clcConfirm  = 0x03
	clcDecline  = 0x04

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

// flow table
type flowTable struct {
	lock sync.Mutex
	fmap map[gopacket.Flow]map[gopacket.Flow]bool
}

// init flow table
func (ft *flowTable) init() {
	ft.lock.Lock()
	if ft.fmap == nil {
		ft.fmap = make(map[gopacket.Flow]map[gopacket.Flow]bool)
	}
	ft.lock.Unlock()
}

// add entry to flow table
func (ft *flowTable) add(net, trans gopacket.Flow) {
	ft.lock.Lock()
	if ft.fmap[net] == nil {
		ft.fmap[net] = make(map[gopacket.Flow]bool)
	}

	ft.fmap[net][trans] = true
	ft.lock.Unlock()
}

// remove entry from flow table
func (ft *flowTable) del(net, trans gopacket.Flow) {
	ft.lock.Lock()
	if ft.fmap[net] != nil {
		delete(ft.fmap[net], trans)
	}
	ft.lock.Unlock()
}

// get entry from flow table
func (ft *flowTable) get(net, trans gopacket.Flow) bool {
	check := false

	ft.lock.Lock()
	if ft.fmap[net] != nil {
		check = ft.fmap[net][trans]
	}
	ft.lock.Unlock()

	return check
}

// SMC eyecatcher
type eyecatcher [4]byte

func (e eyecatcher) String() string {
	if bytes.Compare(e[:], smcrEyecatcher) == 0 {
		return "SMC-R"
	}
	if bytes.Compare(e[:], smcdEyecatcher) == 0 {
		return "SMC-D"
	}
	return "Unknown"
}

// SMC path
type path uint8

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

// SMC peer ID
type peerID [peerIDLen]byte

func (p peerID) String() string {
	instance := binary.BigEndian.Uint16(p[:2])
	roceMAC := net.HardwareAddr(p[2:8])
	return fmt.Sprintf("%d@%s", instance, roceMAC)
}

// SMC QP MTU
type qpMTU uint8

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

// SMC RMBE size
type rmbeSize uint8

func (s rmbeSize) String() string {
	size := 1 << (s + 14)
	return fmt.Sprintf("%d (%d)", s, size)
}

// CLC Proposal Message
type clcProposalMsg struct {
	hdr          *clcMessage
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
}

// convert CLC Proposal to string
func (p *clcProposalMsg) String() string {
	if p == nil {
		return "n/a"
	}

	if *showReserved {
		proposalFmt := "Peer ID: %s, SMC-R GID: %s, RoCE MAC: %s " +
			"IP Area Offset: %d, SMC-D GID: %d, Reserved: %#x " +
			"IPv4 Prefix: %s/%d, Reserved: %#x, " +
			"IPv6 Prefix Count: %d"
		return fmt.Sprintf(proposalFmt, p.senderPeerID, p.ibGID,
			p.ibMAC, p.ipAreaOffset, p.smcdGID, p.reserved,
			p.prefix, p.prefixLen, p.reserved2, p.ipv6PrefixesCnt)
	}
	proposalFmt := "Peer ID: %s, SMC-R GID: %s, RoCE MAC: %s " +
		"IP Area Offset: %d, SMC-D GID: %d, " +
		"IPv4 Prefix: %s/%d, IPv6 Prefix Count: %d"
	return fmt.Sprintf(proposalFmt, p.senderPeerID, p.ibGID, p.ibMAC,
		p.ipAreaOffset, p.smcdGID, p.prefix, p.prefixLen,
		p.ipv6PrefixesCnt)
}

// CLC SMC-R Accept/Confirm Message
type clcSMCRAcceptConfirmMsg struct {
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

// convert CLC SMC-R Accept/Confirm to string
func (ac *clcSMCRAcceptConfirmMsg) String() string {
	if ac == nil {
		return "n/a"
	}

	if *showReserved {
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
	acFmt := "Peer ID: %s, SMC-R GID: %s, RoCE MAC: %s, " +
		"QP Number: %d, RMB RKey: %d, RMBE Index: %d, " +
		"RMBE Alert Token: %d, RMBE Size: %s, QP MTU: %s, " +
		"RMB Virtual Address: %#x, Packet Sequence Number: %d"
	return fmt.Sprintf(acFmt, ac.senderPeerID, ac.ibGID, ac.ibMAC, ac.qpn,
		ac.rmbRkey, ac.rmbeIdx, ac.rmbeAlertToken, ac.rmbeSize,
		ac.qpMtu, ac.rmbDmaAddr, ac.psn)
}

// CLC SMC-D Accept/Confirm Message
type clcSMCDAcceptConfirmMsg struct {
	smcdGID   uint64   /* Sender GID */
	smcdToken uint64   /* DMB token */
	dmbeIdx   uint8    /* DMBE index */
	dmbeSize  rmbeSize /* 4 bits buf size (compressed) */
	reserved  byte     /* 4 bits reserved */
	reserved2 [2]byte
	linkid    uint32 /* Link identifier */
	reserved3 [12]byte
}

// convert CLC SMC-D Accept/Confirm to string
func (ac *clcSMCDAcceptConfirmMsg) String() string {
	if ac == nil {
		return "n/a"
	}

	if *showReserved {
		acFmt := "SMC-D GID: %d, SMC-D Token: %d, DMBE Index %d, " +
			"DMBE Size %s, Reserved: %#x, Reserved: %#x, " +
			"Link ID: %d, Reserved: %#x"
		return fmt.Sprintf(acFmt, ac.smcdGID, ac.smcdToken, ac.dmbeIdx,
			ac.dmbeSize, ac.reserved, ac.reserved2, ac.linkid,
			ac.reserved3)
	}
	acFmt := "SMC-D GID: %d, SMC-D Token: %d, DMBE Index %d, " +
		"DMBE Size %s, Link ID: %d"
	return fmt.Sprintf(acFmt, ac.smcdGID, ac.smcdToken, ac.dmbeIdx,
		ac.dmbeSize, ac.linkid)
}

// CLC Accept/Confirm Message
type clcAcceptConfirmMsg struct {
	hdr  *clcMessage
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

// CLC Decline Message
type clcDeclineMsg struct {
	hdr           *clcMessage
	senderPeerID  peerID /* sender peer_id */
	peerDiagnosis uint32 /* diagnosis information */
	reserved      [4]byte
}

// convert CLC Decline Message to string
func (d *clcDeclineMsg) String() string {
	if d == nil {
		return "n/a"
	}

	// parse peer diagnosis code
	var diag string
	switch d.peerDiagnosis {
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

	if *showReserved {
		declineFmt := "Peer ID: %s, Peer Diagnosis: %s, " +
			"Reserved: %#x"
		return fmt.Sprintf(declineFmt, d.senderPeerID, diag,
			d.reserved)
	}
	declineFmt := "Peer ID: %s, Peer Diagnosis: %s"
	return fmt.Sprintf(declineFmt, d.senderPeerID, diag)
}

// CLC message
type clcMessage struct {
	// eyecatcher
	eyecatcher eyecatcher

	// type of message: proposal, accept, confirm, decline
	typ uint8

	// total length of message
	length uint16

	// 1 byte bitfield containing version, flag, reserved, path:
	version  uint8 // (4 bits)
	first    uint8 // (1 bit)
	reserved byte  // (1 bit)
	path     path  // (2 bits)

	// type depenent message content
	proposal *clcProposalMsg
	accept   *clcAcceptConfirmMsg
	confirm  *clcAcceptConfirmMsg
	decline  *clcDeclineMsg

	// trailer
	trailer eyecatcher
}

// parse CLC message
func (c *clcMessage) parse(buf []byte) {
	// trailer
	copy(c.trailer[:], buf[c.length-4:])
	if !hasEyecatcher(c.trailer[:]) {
		log.Println("Invalid message trailer")
		return
	}

	// parse type dependent message content
	switch c.typ {
	case clcProposal:
		c.proposal = parseCLCProposal(c, buf)
	case clcAccept:
		c.accept = parseCLCAcceptConfirm(c, buf)
	case clcConfirm:
		c.confirm = parseCLCAcceptConfirm(c, buf)
	case clcDecline:
		c.decline = parseCLCDecline(c, buf)
	}
}

// convert header fields to a string
func (c *clcMessage) String() string {
	var typ string
	var msg string

	if c == nil {
		return "n/a"
	}

	// message type
	switch c.typ {
	case clcProposal:
		typ = "Proposal"
		msg = c.proposal.String()
	case clcAccept:
		typ = "Accept"
		msg = c.accept.String()
	case clcConfirm:
		typ = "Confirm"
		msg = c.confirm.String()
	case clcDecline:
		typ = "Decline"
		msg = c.decline.String()
	default:
		typ = "Unknown"
		msg = "n/a"
	}

	// construct string
	if *showReserved {
		headerFmt := "%s: Eyecatcher: %s, Length: %d, Version: %d, " +
			"First Contact: %d, Reserved: %#x, Path: %s, %s, " +
			"Trailer: %s"
		return fmt.Sprintf(headerFmt, typ, c.eyecatcher, c.length,
			c.version, c.first, c.reserved, c.path, msg, c.trailer)
	}
	headerFmt := "%s: Eyecatcher: %s, Length: %d, Version: %d, " +
		"First Contact: %d, Path: %s, %s, Trailer: %s"
	return fmt.Sprintf(headerFmt, typ, c.eyecatcher, c.length, c.version,
		c.first, c.path, msg, c.trailer)
}

// check if there is a SMC-R or SMC-D eyecatcher in the buffer
func hasEyecatcher(buf []byte) bool {
	if bytes.Compare(buf[0:4], smcrEyecatcher) == 0 {
		return true
	}
	if bytes.Compare(buf[0:4], smcdEyecatcher) == 0 {
		return true
	}
	return false
}

// parse CLC Proposal in buffer
func parseCLCProposal(hdr *clcMessage, buf []byte) *clcProposalMsg {
	proposal := clcProposalMsg{}
	proposal.hdr = hdr

	// skip clc header
	buf = buf[clcHeaderLen:]

	// sender peer ID
	copy(proposal.senderPeerID[:], buf[:peerIDLen])
	buf = buf[peerIDLen:]

	// ib GID is an IPv6 address
	proposal.ibGID = make(net.IP, 16)
	copy(proposal.ibGID[:], buf[:16])
	buf = buf[16:]

	// ib MAC is a 6 byte MAC address
	proposal.ibMAC = make(net.HardwareAddr, 6)
	copy(proposal.ibMAC[:], buf[:6])
	buf = buf[6:]

	// offset to ip area
	proposal.ipAreaOffset = binary.BigEndian.Uint16(buf[:2])
	buf = buf[2:]

	// Optional SMC-D info
	if proposal.ipAreaOffset == 40 {
		// smcd GID
		proposal.smcdGID = binary.BigEndian.Uint64(buf[:8])
		buf = buf[8:]

		// reserved
		copy(proposal.reserved[:], buf[:32])
		buf = buf[32:]
	} else {
		buf = buf[proposal.ipAreaOffset:]
	}

	// IP/prefix is an IPv4 address
	proposal.prefix = make(net.IP, 4)
	copy(proposal.prefix[:], buf[:4])
	buf = buf[4:]

	// prefix length
	proposal.prefixLen = uint8(buf[0])
	buf = buf[1:]

	// reserved
	copy(proposal.reserved2[:], buf[:2])
	buf = buf[2:]

	// ipv6 prefix count
	proposal.ipv6PrefixesCnt = uint8(buf[0])

	return &proposal
}

// parse SMC-R Accept/Confirm Message
func parseSMCRAcceptConfirm(
	hdr *clcMessage, buf []byte) *clcSMCRAcceptConfirmMsg {
	ac := clcSMCRAcceptConfirmMsg{}

	// skip clc header
	buf = buf[clcHeaderLen:]

	// sender peer ID
	copy(ac.senderPeerID[:], buf[:peerIDLen])
	buf = buf[peerIDLen:]

	// ib GID is an IPv6 Address
	ac.ibGID = make(net.IP, 16)
	copy(ac.ibGID[:], buf[:16])
	buf = buf[16:]

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

// parse SMC-D Accept/Confirm Message
func parseSMCDAcceptConfirm(
	hdr *clcMessage, buf []byte) *clcSMCDAcceptConfirmMsg {
	ac := clcSMCDAcceptConfirmMsg{}

	// skip clc header
	buf = buf[clcHeaderLen:]

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

	return &ac
}

// parse Accept/Confirm Message
func parseCLCAcceptConfirm(hdr *clcMessage, buf []byte) *clcAcceptConfirmMsg {
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

// parse CLC Decline in buffer
func parseCLCDecline(hdr *clcMessage, buf []byte) *clcDeclineMsg {
	decline := clcDeclineMsg{}
	decline.hdr = hdr

	// skip clc header
	buf = buf[clcHeaderLen:]

	// sender peer ID
	copy(decline.senderPeerID[:], buf[:peerIDLen])
	buf = buf[peerIDLen:]

	// peer diagnosis
	decline.peerDiagnosis = binary.BigEndian.Uint32(buf[:4])
	buf = buf[4:]

	// reserved
	copy(decline.reserved[:], buf[:4])
	buf = buf[4:]

	return &decline
}

// parse CLC header in buffer
func parseCLCHeader(buf []byte) *clcMessage {
	header := clcMessage{}

	// check eyecatcher first
	if !hasEyecatcher(buf) {
		return nil
	}

	// eyecatcher
	copy(header.eyecatcher[:], buf[0:4])

	// type
	header.typ = buf[4]

	// length
	header.length = binary.BigEndian.Uint16(buf[5:7])

	// 1 byte bitfield: version, flag, reserved, path
	bitfield := buf[7]
	header.version = (bitfield & 0b11110000) >> 4
	header.first = (bitfield & 0b00001000) >> 3
	header.reserved = (bitfield & 0b00000100) >> 2
	header.path = path(bitfield & 0b00000011)

	return &header
}

// smcStreamFactory implementing tcpassembly.StreamFactory
type smcStreamFactory struct{}

// smcStream for decoding of smc packets
type smcStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
}

// create new smc stream factory (-> implement tcpassembly.StreamFactory)
func (h *smcStreamFactory) New(
	net, transport gopacket.Flow) tcpassembly.Stream {
	sstream := &smcStream{
		net:       net,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
	}
	go sstream.run() // parse stream in goroutine

	// ReaderStream implements tcpassembly.Stream, so we can return a
	// pointer to it.
	return &sstream.r
}

// print CLC info of stream
func printCLC(s *smcStream, clc *clcMessage) {
	clcFmt := "%s%s:%s -> %s:%s: %s\n"
	t := ""

	if *showTimestamps {
		t = time.Now().Format("15:04:05.000000 ")
	}
	fmt.Printf(clcFmt, t, s.net.Src(), s.transport.Src(), s.net.Dst(),
		s.transport.Dst(), clc)
}

// parse smc stream
func (s *smcStream) run() {
	var clc *clcMessage
	buf := make([]byte, 2048)
	// get at least enough bytes for the CLC header
	skip := clcHeaderLen
	eof := false
	total := 0

	for {
		// try to read enough data into buffer and check EOF and errors
		for total < skip && !eof {
			n, err := s.r.Read(buf[total:])
			if err != nil {
				if err != io.EOF {
					log.Println("Error reading stream:",
						err)
				}
				eof = true
			}
			total += n
		}

		// parse and print current CLC message
		if clc != nil {
			// parse and print message
			clc.parse(buf[skip-int(clc.length):])
			printCLC(s, clc)

			// wait for next handshake message
			clc = nil
			skip += clcHeaderLen
			continue

		}

		// if there is not enough data left in buffer, we are done
		if total < skip {
			break
		}

		// parse header of current CLC message
		clc = parseCLCHeader(buf[skip-clcHeaderLen:])
		if clc == nil {
			break
		}

		// skip to end of current message to be able to parse it
		skip += int(clc.length) - clcHeaderLen
	}

	// discard everything
	tcpreader.DiscardBytesToEOF(&s.r)
}

// ReassemblyComplete is called when the TCP assembler believes the stream has
// finished
func (s *smcStream) ReassemblyComplete() {
	// remove entry from flow table
	flows.del(s.net, s.transport)
}

// check if SMC option is set in TCP header
func checkSMCOption(tcp *layers.TCP) bool {
	for _, opt := range tcp.Options {
		if opt.OptionType == 254 &&
			opt.OptionLength == 6 &&
			bytes.Compare(opt.OptionData, smcOption) == 0 {
			return true
		}
	}

	return false
}

// handle packet
func handlePacket(assembler *tcpassembly.Assembler, packet gopacket.Packet) {
	// only handle tcp packets (with valid network layer)
	if packet.NetworkLayer() == nil ||
		packet.TransportLayer() == nil ||
		packet.TransportLayer().LayerType() !=
			layers.LayerTypeTCP {
		return
	}
	tcp, ok := packet.TransportLayer().(*layers.TCP)
	if !ok {
		log.Fatal("Error parsing TCP packet")
	}

	// if smc option is set, try to parse tcp stream
	nflow := packet.NetworkLayer().NetworkFlow()
	tflow := packet.TransportLayer().TransportFlow()
	if checkSMCOption(tcp) || flows.get(nflow, tflow) {
		flows.add(nflow, tflow)
		assembler.AssembleWithTimestamp(nflow, tcp,
			packet.Metadata().Timestamp)
	}
}

// handle timer event
func handleTimer(assembler *tcpassembly.Assembler) {
	flushedFmt := "Timer: flushed %d, closed %d connections\n"

	// flush connections without activity in the past minute
	flushed, closed := assembler.FlushOlderThan(time.Now().Add(
		-time.Minute))
	if flushed > 0 {
		fmt.Printf(flushedFmt, flushed, closed)
	}
}

// listen on network interface and parse packets
func listen() {
	pcapSnaplen := int32(1024)

	// open device
	pcapHandle, pcapErr := pcap.OpenLive(*pcapDevice, pcapSnaplen,
		*pcapPromisc, pcap.BlockForever)
	if pcapErr != nil {
		log.Fatal(pcapErr)
	}
	defer pcapHandle.Close()

	// Set up assembly
	streamFactory := &smcStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	// init flow table
	flows.init()

	// Use the handle as a packet source to process all packets
	fmt.Printf("Starting to listen on interface %s.\n", *pcapDevice)
	packetSource := gopacket.NewPacketSource(pcapHandle,
		pcapHandle.LinkType())
	packets := packetSource.Packets()

	// setup timer
	ticker := time.Tick(time.Minute)

	// handle packets and timer events
	for {
		select {
		case packet := <-packets:
			handlePacket(assembler, packet)
		case <-ticker:
			handleTimer(assembler)
		}
	}
}

// main
func main() {
	flag.Parse()
	listen()
}
