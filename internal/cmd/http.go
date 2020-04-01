package cmd

import (
	"github.com/hwipl/smc-go/pkg/util"
)

// setHTTPOutput sets the standard output to http and starts a http server
func setHTTPOutput() {
	h := util.StartHTTPOutput(*httpListen)
	stdout = &h.Buffer
	stderr = &h.Buffer
}
