package messages

import (
	"encoding/hex"
	"log"
	"testing"
)

func TestParseCLCHeaderProposal(t *testing.T) {
	// prepare message
	msg_bytes := "e2d4c3d901003410b1a098039babcdef" +
		"fe800000000000009a039bfffeabcdef" +
		"98039babcdef00007f00000008000000" +
		"e2d4c3d9"
	msg, err := hex.DecodeString(msg_bytes)
	if err != nil {
		log.Fatal(err)
	}

	// parse message
	clc := ParseCLCHeader(msg)
	clc.Parse(msg)

	// check output message without reserved fields
	want := "Proposal: Eyecatcher: SMC-R, Type: 1 (Proposal), " +
		"Length: 52, Version: 1, Flag: 0, Path: SMC-R, " +
		clc.proposal.String() + ", Trailer: SMC-R"
	got := clc.String()
	if got != want {
		t.Errorf("clc.String() = %s; want %s", got, want)
	}

	// check output message with reserved fields
	want = "Proposal: Eyecatcher: SMC-R, Type: 1 (Proposal), " +
		"Length: 52, Version: 1, Flag: 0, Reserved: 0x0, " +
		"Path: SMC-R, " + clc.proposal.Reserved() + ", Trailer: SMC-R"
	got = clc.Reserved()
	if got != want {
		t.Errorf("clc.Reserved() = %s; want %s", got, want)
	}
}

func TestParseCLCHeaderDecline(t *testing.T) {
	// prepare message
	msg_bytes := "e2d4c3d904001c102525252525252500" +
		"0303000000000000e2d4c3d9"
	msg, err := hex.DecodeString(msg_bytes)
	if err != nil {
		log.Fatal(err)
	}

	// parse message
	clc := ParseCLCHeader(msg)
	clc.Parse(msg)

	// check output message without reserved fields
	want := "Decline: Eyecatcher: SMC-R, Type: 4 (Decline), Length: 28, " +
		"Version: 1, Out of Sync: 0, Path: SMC-R, " +
		clc.decline.String() + ", Trailer: SMC-R"
	got := clc.String()
	if got != want {
		t.Errorf("clc.String() = %s; want %s", got, want)
	}

	// check output message with reserved fields
	want = "Decline: Eyecatcher: SMC-R, Type: 4 (Decline), Length: 28, " +
		"Version: 1, Out of Sync: 0, Reserved: 0x0, Path: SMC-R, " +
		clc.decline.Reserved() + ", Trailer: SMC-R"
	got = clc.Reserved()
	if got != want {
		t.Errorf("clc.Reserved() = %s; want %s", got, want)
	}
}
