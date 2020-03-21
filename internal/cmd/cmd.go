package cmd

import (
	"flag"
	"io"
	"log"
	"os"
)

var (
	// pcap variables
	pcapFile    = flag.String("f", "", "the pcap file to read")
	pcapDevice  = flag.String("i", "", "the interface to listen on")
	pcapPromisc = flag.Bool("promisc", true, "promiscuous mode")
	pcapSnaplen = flag.Int("snaplen", 2048, "pcap snaplen in byte")
	pcapTimeout = flag.Int("timeout", 0, "pcap timeout in ms")
	pcapMaxPkts = flag.Int("maxpkts", 0,
		"maximum packets to capture (may require timeout argument)")
	pcapMaxTime = flag.Int("maxtime", 0,
		"maximum capturing time in s (may require timeout argument)")
	pcapFilter = flag.String("filter", "", "pcap packet filter")

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
		setHTTPOutput()
	}
	log.SetOutput(stderr)
	listen()
}
