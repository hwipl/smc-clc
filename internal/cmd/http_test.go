package cmd

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"testing"
)

func getHTTPBody(url string) string {
	resp, err := http.Get(url)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	return fmt.Sprintf("%s", body)
}

func TestPrintHTTP(t *testing.T) {
	var want, got, url string

	// create custom listener with random port
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		log.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port

	// start http server
	http.HandleFunc("/", printHTTP)
	go http.Serve(listener, nil)

	// get url with empty http buffer
	url = fmt.Sprintf("http://localhost:%d/", port)
	want = ""
	got = getHTTPBody(url)
	if got != want {
		t.Errorf("got = %s; want %s", got, want)
	}

	// get url with filled http buffer
	url = fmt.Sprintf("http://localhost:%d/", port)
	want = "hello world"
	fmt.Fprintf(&httpBuffer, want)
	got = getHTTPBody(url)
	if got != want {
		t.Errorf("got = %s; want %s", got, want)
	}

	// get url (two times) with wrong flush, should not change reply
	url = fmt.Sprintf("http://localhost:%d/?flush=wrong", port)
	want = "hello world"
	got = getHTTPBody(url)
	got = getHTTPBody(url)
	if got != want {
		t.Errorf("got = %s; want %s", got, want)
	}

	// get url with flush
	url = fmt.Sprintf("http://localhost:%d/?flush=true", port)
	want = "hello world"
	got = getHTTPBody(url)
	if got != want {
		t.Errorf("got = %s; want %s", got, want)
	}

	// get url again after flush, should return nothing
	url = fmt.Sprintf("http://localhost:%d/", port)
	want = ""
	got = getHTTPBody(url)
	if got != want {
		t.Errorf("got = %s; want %s", got, want)
	}
}
