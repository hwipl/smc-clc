package cmd

import (
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/hwipl/smc-go/pkg/util"
)

var (
	httpBuffer util.Buffer
)

// printHTTP prints the httpBuffer to http clients
func printHTTP(w http.ResponseWriter, r *http.Request) {
	b := httpBuffer.CopyBuffer()
	if _, err := io.Copy(w, b); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	flush := r.URL.Query().Get("flush")
	if flush == "true" {
		httpBuffer.Reset()
	}
}

// setHTTPOutput sets the standard output to http and starts a http server
func setHTTPOutput() {
	stdout = &httpBuffer
	stderr = &httpBuffer

	http.HandleFunc("/", printHTTP)
	go http.ListenAndServe(*httpListen, nil)
}
