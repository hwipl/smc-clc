package messages

import (
	"bytes"

	"github.com/google/gopacket/layers"
)

var (
	smcOption = smcrEyecatcher
)

// CheckSMCOption checks if SMC option is set in TCP header
func CheckSMCOption(tcp *layers.TCP) bool {
	for _, opt := range tcp.Options {
		if opt.OptionType == 254 &&
			opt.OptionLength == 6 &&
			bytes.Compare(opt.OptionData, smcOption) == 0 {
			return true
		}
	}

	return false
}
