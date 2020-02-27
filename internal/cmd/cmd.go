package cmd

import (
	"flag"
	"io"
	"log"
	"os"
)

var (
	// pcap variables
	pcapDevice  = flag.String("i", "eth0", "the interface to listen on")
	pcapPromisc = flag.Bool("promisc", true, "promiscuous mode")
	pcapSnaplen = flag.Int("snaplen", 2048, "pcap snaplen")

	// display variables
	showReserved = flag.Bool("reserved", false,
		"print reserved values in messages")
	showTimestamps = flag.Bool("timestamps", true, "print timestamps")
	showDumps      = flag.Bool("dumps", false, "print message hex dumps")

	// output, changed by http output
	stdout     io.Writer = os.Stdout
	stderr     io.Writer = os.Stderr
	httpListen           = flag.String("http", "",
		"use http server and set listen address (e.g.: :8000)")
)

// Run is the main entry point of the smc-clc program: it parses the command
// line arguments, starts the http server (if enabled via the command line),
// and starts handling packets
func Run() {
	flag.Parse()
	if *httpListen != "" {
		setHttpOutput()
	}
	log.SetOutput(stderr)
	listen()
}
