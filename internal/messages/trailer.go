package messages

import "log"

const (
	clcTrailerLen = clcEyecatcherLen
)

// trailer stores a CLC message trailer
type trailer eyecatcher

// Parse parses the CLC message trailer at the end of buf
func (t *trailer) Parse(buf []byte) {
	copy(t[:], buf[len(buf)-clcTrailerLen:])
	if !hasEyecatcher(t[:]) {
		log.Println("Error parsing CLC message: invalid trailer")
		errDump(buf[len(buf)-clcTrailerLen:])
		return
	}
}

// String converts the message trailer to a string
func (t trailer) String() string {
	return eyecatcher(t).String()
}
