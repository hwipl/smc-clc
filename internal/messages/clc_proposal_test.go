package messages

import (
	"encoding/hex"
	"log"
	"testing"
)

func TestParseCLCProposalSMCRIPv4(t *testing.T) {
	// prepare smc-r ipv4 proposal message
	ipv4_proposal := "e2d4c3d901003410b1a098039babcdef" +
		"fe800000000000009a039bfffeabcdef" +
		"98039babcdef00007f00000008000000" +
		"e2d4c3d9"
	msg, err := hex.DecodeString(ipv4_proposal)
	if err != nil {
		log.Fatal(err)
	}

	// parse message
	clc_hdr := ParseCLCHeader(msg)
	proposal := parseCLCProposal(clc_hdr, msg)

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

func TestParseCLCProposalSMCRIPv6(t *testing.T) {
	// prepare smc-r ipv6 proposal message
	ipv6_proposal := "e2d4c3d901004510394498039babcdef" +
		"fe800000000000009a039bfffeabcdef" +
		"98039babcdef00000000000000000001" +
		"00000000000000000000000000000001" +
		"80e2d4c3d9"
	msg, err := hex.DecodeString(ipv6_proposal)
	if err != nil {
		log.Fatal(err)
	}

	// parse message
	clc_hdr := ParseCLCHeader(msg)
	proposal := parseCLCProposal(clc_hdr, msg)

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
