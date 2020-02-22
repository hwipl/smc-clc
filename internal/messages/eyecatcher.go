package messages

import "bytes"

var (
	smcrEyecatcher = []byte{0xE2, 0xD4, 0xC3, 0xD9}
	smcdEyecatcher = []byte{0xE2, 0xD4, 0xC3, 0xC4}
)

const (
	clcEyecatcherLen = 4
	clcTrailerLen    = clcEyecatcherLen
)

// SMC eyecatcher
type eyecatcher [clcEyecatcherLen]byte

func (e eyecatcher) String() string {
	if bytes.Compare(e[:], smcrEyecatcher) == 0 {
		return "SMC-R"
	}
	if bytes.Compare(e[:], smcdEyecatcher) == 0 {
		return "SMC-D"
	}
	return "Unknown"
}

// check if there is a SMC-R or SMC-D eyecatcher in the buffer
func hasEyecatcher(buf []byte) bool {
	if bytes.Compare(buf[:clcEyecatcherLen], smcrEyecatcher) == 0 {
		return true
	}
	if bytes.Compare(buf[:clcEyecatcherLen], smcdEyecatcher) == 0 {
		return true
	}
	return false
}
