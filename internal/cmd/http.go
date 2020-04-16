package cmd

import (
	"github.com/hwipl/smc-go/pkg/http"
)

// setHTTPOutput sets the standard output to http and starts a http server
func setHTTPOutput() {
	h := http.StartServer(*httpListen)
	stdout = &h.Buffer
	stderr = &h.Buffer
}
