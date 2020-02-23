package messages

import (
	"encoding/hex"
	"log"
	"testing"
)

func TestParseCLCDecline(t *testing.T) {
	// prepare decline message
	declineMsg := "e2d4c3d904001c102525252525252500" +
		"0303000000000000e2d4c3d9"
	msg, err := hex.DecodeString(declineMsg)
	if err != nil {
		log.Fatal(err)
	}

	// parse message
	clcHdr := ParseCLCHeader(msg)
	decline := parseCLCDecline(clcHdr, msg)

	// check output message without reserved fields
	want := "Peer ID: 9509@25:25:25:25:25:00, " +
		"Peer Diagnosis: 0x3030000 (no SMC device found (R or D))"
	got := decline.String()
	if got != want {
		t.Errorf("decline.String() = %s; want %s", got, want)
	}

	// check output message with reserved fields
	want = "Peer ID: 9509@25:25:25:25:25:00, " +
		"Peer Diagnosis: 0x3030000 (no SMC device found (R or D)), " +
		"Reserved: 0x00000000"
	got = decline.Reserved()
	if got != want {
		t.Errorf("decline.Reserved() = %s; want %s", got, want)
	}

}