package messages

import (
	"encoding/hex"
	"log"
	"testing"
)

func TestParseCLCProposalSMCRIPv4(t *testing.T) {
	// prepare smc-r ipv4 proposal message
	ipv4Proposal := "e2d4c3d901003410b1a098039babcdef" +
		"fe800000000000009a039bfffeabcdef" +
		"98039babcdef00007f00000008000000" +
		"e2d4c3d9"
	msg, err := hex.DecodeString(ipv4Proposal)
	if err != nil {
		log.Fatal(err)
	}

	// parse message
	clcHdr := ParseCLCHeader(msg)
	proposal := parseCLCProposal(clcHdr, msg)

	// check output message without reserved fields
	want := "Peer ID: 45472@98:03:9b:ab:cd:ef, " +
		"SMC-R GID: fe80::9a03:9bff:feab:cdef, " +
		"RoCE MAC: 98:03:9b:ab:cd:ef, IP Area Offset: 0, " +
		"SMC-D GID: 0, IPv4 Prefix: 127.0.0.0/8, " +
		"IPv6 Prefix Count: 0"
	got := proposal.String()
	if got != want {
		t.Errorf("proposal.String() = %s; want %s", got, want)
	}

	// check output message with reserved fields
	want = "Peer ID: 45472@98:03:9b:ab:cd:ef, " +
		"SMC-R GID: fe80::9a03:9bff:feab:cdef, " +
		"RoCE MAC: 98:03:9b:ab:cd:ef, IP Area Offset: 0, " +
		"SMC-D GID: 0, Reserved: 0x000000000000000000000000000000000" +
		"0000000000000000000000000000000, IPv4 Prefix: 127.0.0.0/8, " +
		"Reserved: 0x0000, IPv6 Prefix Count: 0"
	got = proposal.Reserved()
	if got != want {
		t.Errorf("proposal.Reserved() = %s; want %s", got, want)
	}
}

func TestParseCLCProposalSMCDIPv4(t *testing.T) {
	// prepare smc-d ipv4 proposal message
	ipv4Proposal := "e2d4c3c401005c11b1a098039babcdef" +
		"00000000000000000000000000000000" +
		"00000000000000280123456789abcdef" +
		"00000000000000000000000000000000" +
		"00000000000000000000000000000000" +
		"7f00000008000000e2d4c3c4"
	msg, err := hex.DecodeString(ipv4Proposal)
	if err != nil {
		log.Fatal(err)
	}

	// parse message
	clcHdr := ParseCLCHeader(msg)
	proposal := parseCLCProposal(clcHdr, msg)

	// check output message without reserved fields
	want := "Peer ID: 45472@98:03:9b:ab:cd:ef, SMC-R GID: ::, " +
		"RoCE MAC: 00:00:00:00:00:00, IP Area Offset: 40, " +
		"SMC-D GID: 81985529216486895, IPv4 Prefix: 127.0.0.0/8, " +
		"IPv6 Prefix Count: 0"
	got := proposal.String()
	if got != want {
		t.Errorf("proposal.String() = %s; want %s", got, want)
	}

	// check output message with reserved fields
	want = "Peer ID: 45472@98:03:9b:ab:cd:ef, SMC-R GID: ::, " +
		"RoCE MAC: 00:00:00:00:00:00, IP Area Offset: 40, " +
		"SMC-D GID: 81985529216486895, Reserved: 0x00000000000000000" +
		"00000000000000000000000000000000000000000000000, " +
		"IPv4 Prefix: 127.0.0.0/8, Reserved: 0x0000, " +
		"IPv6 Prefix Count: 0"
	got = proposal.Reserved()
	if got != want {
		t.Errorf("proposal.Reserved() = %s; want %s", got, want)
	}
}

func TestParseCLCProposalSMCBIPv4(t *testing.T) {
	// prepare smc-b (r + d) ipv4 proposal message
	ipv4Proposal := "e2d4c3d901005c13b1a098039babcdef" +
		"fe800000000000009a039bfffeabcdef" +
		"98039babcdef00280123456789abcdef" +
		"00000000000000000000000000000000" +
		"00000000000000000000000000000000" +
		"7f00000008000000e2d4c3d9"
	msg, err := hex.DecodeString(ipv4Proposal)
	if err != nil {
		log.Fatal(err)
	}

	// parse message
	clcHdr := ParseCLCHeader(msg)
	proposal := parseCLCProposal(clcHdr, msg)

	// check output message without reserved fields
	want := "Peer ID: 45472@98:03:9b:ab:cd:ef, " +
		"SMC-R GID: fe80::9a03:9bff:feab:cdef, " +
		"RoCE MAC: 98:03:9b:ab:cd:ef, IP Area Offset: 40, " +
		"SMC-D GID: 81985529216486895, IPv4 Prefix: 127.0.0.0/8, " +
		"IPv6 Prefix Count: 0"
	got := proposal.String()
	if got != want {
		t.Errorf("proposal.String() = %s; want %s", got, want)
	}

	// check output message with reserved fields
	want = "Peer ID: 45472@98:03:9b:ab:cd:ef, " +
		"SMC-R GID: fe80::9a03:9bff:feab:cdef, " +
		"RoCE MAC: 98:03:9b:ab:cd:ef, IP Area Offset: 40, " +
		"SMC-D GID: 81985529216486895, Reserved: 0x00000000000000000" +
		"00000000000000000000000000000000000000000000000, " +
		"IPv4 Prefix: 127.0.0.0/8, Reserved: 0x0000, " +
		"IPv6 Prefix Count: 0"
	got = proposal.Reserved()
	if got != want {
		t.Errorf("proposal.Reserved() = %s; want %s", got, want)
	}
}

func TestParseCLCProposalSMCRIPv6(t *testing.T) {
	// prepare smc-r ipv6 proposal message
	ipv6Proposal := "e2d4c3d901004510394498039babcdef" +
		"fe800000000000009a039bfffeabcdef" +
		"98039babcdef00000000000000000001" +
		"00000000000000000000000000000001" +
		"80e2d4c3d9"
	msg, err := hex.DecodeString(ipv6Proposal)
	if err != nil {
		log.Fatal(err)
	}

	// parse message
	clcHdr := ParseCLCHeader(msg)
	proposal := parseCLCProposal(clcHdr, msg)

	// check output message without reserved fields
	want := "Peer ID: 14660@98:03:9b:ab:cd:ef, " +
		"SMC-R GID: fe80::9a03:9bff:feab:cdef, " +
		"RoCE MAC: 98:03:9b:ab:cd:ef, IP Area Offset: 0, " +
		"SMC-D GID: 0, IPv4 Prefix: 0.0.0.0/0, " +
		"IPv6 Prefix Count: 1, IPv6 Prefix: ::1/128"
	got := proposal.String()
	if got != want {
		t.Errorf("proposal.String() = %s; want %s", got, want)
	}

	// check output message with reserved fields
	want = "Peer ID: 14660@98:03:9b:ab:cd:ef, " +
		"SMC-R GID: fe80::9a03:9bff:feab:cdef, " +
		"RoCE MAC: 98:03:9b:ab:cd:ef, IP Area Offset: 0, " +
		"SMC-D GID: 0, Reserved: 0x000000000000000000000000000000000" +
		"0000000000000000000000000000000, IPv4 Prefix: 0.0.0.0/0, " +
		"Reserved: 0x0000, IPv6 Prefix Count: 1, IPv6 Prefix: ::1/128"
	got = proposal.Reserved()
	if got != want {
		t.Errorf("proposal.Reserved() = %s; want %s", got, want)
	}
}

func TestParseCLCProposalSMCBIPv6(t *testing.T) {
	// prepare smc-b (r + d) ipv6 proposal message
	ipv6Proposal := "e2d4c3d901006d13394498039babcdef" +
		"fe800000000000009a039bfffeabcdef" +
		"98039babcdef00280123456789abcdef" +
		"00000000000000000000000000000000" +
		"00000000000000000000000000000000" +
		"00000000000000010000000000000000" +
		"000000000000000180e2d4c3d9"
	msg, err := hex.DecodeString(ipv6Proposal)
	if err != nil {
		log.Fatal(err)
	}

	// parse message
	clcHdr := ParseCLCHeader(msg)
	proposal := parseCLCProposal(clcHdr, msg)

	// check output message without reserved fields
	want := "Peer ID: 14660@98:03:9b:ab:cd:ef, " +
		"SMC-R GID: fe80::9a03:9bff:feab:cdef, " +
		"RoCE MAC: 98:03:9b:ab:cd:ef, IP Area Offset: 40, " +
		"SMC-D GID: 81985529216486895, IPv4 Prefix: 0.0.0.0/0, " +
		"IPv6 Prefix Count: 1, IPv6 Prefix: ::1/128"
	got := proposal.String()
	if got != want {
		t.Errorf("proposal.String() = %s; want %s", got, want)
	}

	// check output message with reserved fields
	want = "Peer ID: 14660@98:03:9b:ab:cd:ef, " +
		"SMC-R GID: fe80::9a03:9bff:feab:cdef, " +
		"RoCE MAC: 98:03:9b:ab:cd:ef, IP Area Offset: 40, " +
		"SMC-D GID: 81985529216486895, Reserved: 0x000000000000000" +
		"0000000000000000000000000000000000000000000000000, " +
		"IPv4 Prefix: 0.0.0.0/0, Reserved: 0x0000, " +
		"IPv6 Prefix Count: 1, IPv6 Prefix: ::1/128"
	got = proposal.Reserved()
	if got != want {
		t.Errorf("proposal.Reserved() = %s; want %s", got, want)
	}
}
