package cmd

import (
	"fmt"
	"io"
	"net/http"
	"os"
)

var (
	httpBuffer buffer
)

// printHttp prints the httpBuffer to http clients
func printHttp(w http.ResponseWriter, r *http.Request) {
	b := httpBuffer.copyBuffer()
	if _, err := io.Copy(w, b); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}

// setHttpOutput sets the standard output to http and starts a http server
func setHttpOutput() {
	stdout = &httpBuffer
	stderr = &httpBuffer

	http.HandleFunc("/", printHttp)
	go http.ListenAndServe(*httpListen, nil)
}
