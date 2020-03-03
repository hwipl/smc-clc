package messages

import (
	"encoding/hex"
	"log"
	"testing"
)

func TestParseCLCHeaderProposal(t *testing.T) {
	// prepare message
	msgBytes := "e2d4c3d901003410b1a098039babcdef" +
		"fe800000000000009a039bfffeabcdef" +
		"98039babcdef00007f00000008000000" +
		"e2d4c3d9"
	msg, err := hex.DecodeString(msgBytes)
	if err != nil {
		log.Fatal(err)
	}

	// parse message
	clc := ParseCLCHeader(msg)
	clc.Parse(msg)

	// check output message without reserved fields
	want := "Proposal: Eyecatcher: SMC-R, Type: 1 (Proposal), " +
		"Length: 52, Version: 1, Flag: 0, Path: SMC-R, " +
		clc.message.String() + ", Trailer: SMC-R"
	got := clc.String()
	if got != want {
		t.Errorf("clc.String() = %s; want %s", got, want)
	}

	// check output message with reserved fields
	want = "Proposal: Eyecatcher: SMC-R, Type: 1 (Proposal), " +
		"Length: 52, Version: 1, Flag: 0, Reserved: 0x0, " +
		"Path: SMC-R, " + clc.message.Reserved() + ", Trailer: SMC-R"
	got = clc.Reserved()
	if got != want {
		t.Errorf("clc.Reserved() = %s; want %s", got, want)
	}
}

func TestParseCLCHeaderAccept(t *testing.T) {
	// prepare message
	msgBytes := "e2d4c3d902004418b1a098039babcdef" +
		"fe800000000000009a039bfffeabcdef" +
		"98039babcdef0000e40000157d010000" +
		"0005230000000000f0a600000072f5fe" +
		"e2d4c3d9"
	msg, err := hex.DecodeString(msgBytes)
	if err != nil {
		log.Fatal(err)
	}

	// parse message
	clc := ParseCLCHeader(msg)
	clc.Parse(msg)

	// check output message without reserved fields
	want := "Accept: Eyecatcher: SMC-R, Type: 2 (Accept), " +
		"Length: 68, Version: 1, First Contact: 1, Path: SMC-R, " +
		clc.message.String() + ", Trailer: SMC-R"
	got := clc.String()
	if got != want {
		t.Errorf("clc.String() = %s; want %s", got, want)
	}

	// check output message with reserved fields
	want = "Accept: Eyecatcher: SMC-R, Type: 2 (Accept), " +
		"Length: 68, Version: 1, First Contact: 1, Reserved: 0x0, " +
		"Path: SMC-R, " + clc.message.Reserved() + ", Trailer: SMC-R"
	got = clc.Reserved()
	if got != want {
		t.Errorf("clc.Reserved() = %s; want %s", got, want)
	}
}

func TestParseCLCHeaderAcceptSMCD(t *testing.T) {
	// prepare message
	msgBytes := "e2d4c3c4020030110123456789abcdef" +
		"0123456789abcdefff100000ffffffff" +
		"000000000000000000000000e2d4c3c4"
	msg, err := hex.DecodeString(msgBytes)
	if err != nil {
		log.Fatal(err)
	}

	// parse message
	clc := ParseCLCHeader(msg)
	clc.Parse(msg)

	// check output message without reserved fields
	want := "Accept: Eyecatcher: SMC-D, Type: 2 (Accept), " +
		"Length: 48, Version: 1, First Contact: 0, Path: SMC-D, " +
		clc.message.String() + ", Trailer: SMC-D"
	got := clc.String()
	if got != want {
		t.Errorf("clc.String() = %s; want %s", got, want)
	}

	// check output message with reserved fields
	want = "Accept: Eyecatcher: SMC-D, Type: 2 (Accept), " +
		"Length: 48, Version: 1, First Contact: 0, Reserved: 0x0, " +
		"Path: SMC-D, " + clc.message.Reserved() + ", Trailer: SMC-D"
	got = clc.Reserved()
	if got != want {
		t.Errorf("clc.Reserved() = %s; want %s", got, want)
	}
}

func TestParseCLCHeaderConfirm(t *testing.T) {
	// prepare message
	msgBytes := "e2d4c3d903004410b1a098039babcdef" +
		"fe800000000000009a039bfffeabcdef" +
		"98039babcdef0000e50000187f010000" +
		"0006230000000000f0a40000000d89a4" +
		"e2d4c3d9"
	msg, err := hex.DecodeString(msgBytes)
	if err != nil {
		log.Fatal(err)
	}

	// parse message
	clc := ParseCLCHeader(msg)
	clc.Parse(msg)

	// check output message without reserved fields
	want := "Confirm: Eyecatcher: SMC-R, Type: 3 (Confirm), " +
		"Length: 68, Version: 1, Flag: 0, Path: SMC-R, " +
		clc.message.String() + ", Trailer: SMC-R"
	got := clc.String()
	if got != want {
		t.Errorf("clc.String() = %s; want %s", got, want)
	}

	// check output message with reserved fields
	want = "Confirm: Eyecatcher: SMC-R, Type: 3 (Confirm), " +
		"Length: 68, Version: 1, Flag: 0, Reserved: 0x0, " +
		"Path: SMC-R, " + clc.message.Reserved() + ", Trailer: SMC-R"
	got = clc.Reserved()
	if got != want {
		t.Errorf("clc.Reserved() = %s; want %s", got, want)
	}
}

func TestParseCLCHeaderConfirmSMCD(t *testing.T) {
	// prepare message
	msgBytes := "e2d4c3c4030030110123456789abcdef" +
		"0123456789abcdefff100000ffffffff" +
		"000000000000000000000000e2d4c3c4"
	msg, err := hex.DecodeString(msgBytes)
	if err != nil {
		log.Fatal(err)
	}

	// parse message
	clc := ParseCLCHeader(msg)
	clc.Parse(msg)

	// check output message without reserved fields
	want := "Confirm: Eyecatcher: SMC-D, Type: 3 (Confirm), " +
		"Length: 48, Version: 1, Flag: 0, Path: SMC-D, " +
		clc.message.String() + ", Trailer: SMC-D"
	got := clc.String()
	if got != want {
		t.Errorf("clc.String() = %s; want %s", got, want)
	}

	// check output message with reserved fields
	want = "Confirm: Eyecatcher: SMC-D, Type: 3 (Confirm), " +
		"Length: 48, Version: 1, Flag: 0, Reserved: 0x0, " +
		"Path: SMC-D, " + clc.message.Reserved() + ", Trailer: SMC-D"
	got = clc.Reserved()
	if got != want {
		t.Errorf("clc.Reserved() = %s; want %s", got, want)
	}
}

func TestParseCLCHeaderDecline(t *testing.T) {
	// prepare message
	msgBytes := "e2d4c3d904001c102525252525252500" +
		"0303000000000000e2d4c3d9"
	msg, err := hex.DecodeString(msgBytes)
	if err != nil {
		log.Fatal(err)
	}

	// parse message
	clc := ParseCLCHeader(msg)
	clc.Parse(msg)

	// check output message without reserved fields
	want := "Decline: Eyecatcher: SMC-R, Type: 4 (Decline), Length: 28, " +
		"Version: 1, Out of Sync: 0, Path: SMC-R, " +
		clc.message.String() + ", Trailer: SMC-R"
	got := clc.String()
	if got != want {
		t.Errorf("clc.String() = %s; want %s", got, want)
	}

	// check output message with reserved fields
	want = "Decline: Eyecatcher: SMC-R, Type: 4 (Decline), Length: 28, " +
		"Version: 1, Out of Sync: 0, Reserved: 0x0, Path: SMC-R, " +
		clc.message.Reserved() + ", Trailer: SMC-R"
	got = clc.Reserved()
	if got != want {
		t.Errorf("clc.Reserved() = %s; want %s", got, want)
	}
}
