package clc

import "bytes"

var (
	smcrEyecatcher = []byte{0xE2, 0xD4, 0xC3, 0xD9}
	smcdEyecatcher = []byte{0xE2, 0xD4, 0xC3, 0xC4}
)

const (
	eyecatcherLen = 4
)

// eyecatcher stores a SMC eyecatcher
type eyecatcher [eyecatcherLen]byte

// String converts the eyecatcher to a string
func (e eyecatcher) String() string {
	if bytes.Compare(e[:], smcrEyecatcher) == 0 {
		return "SMC-R"
	}
	if bytes.Compare(e[:], smcdEyecatcher) == 0 {
		return "SMC-D"
	}
	return "Unknown"
}

// hasEyecatcher checks if there is a SMC-R or SMC-D eyecatcher in buf
func hasEyecatcher(buf []byte) bool {
	if bytes.Compare(buf[:eyecatcherLen], smcrEyecatcher) == 0 {
		return true
	}
	if bytes.Compare(buf[:eyecatcherLen], smcdEyecatcher) == 0 {
		return true
	}
	return false
}
