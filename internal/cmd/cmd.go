package cmd

import (
	"flag"
	"io"
	"log"
	"os"
)

var (
	// pcap variables
	pcapFile = flag.String("f", "",
		"read packets from a pcap file and set it to `file`")
	pcapDevice = flag.String("i", "", "read packets from "+
		"a network interface (default) and set it to `interface`")
	pcapPromisc = flag.Bool("pcap-promisc", true,
		"set network interface to promiscuous mode")
	pcapSnaplen = flag.Int("pcap-snaplen", 2048,
		"set pcap snaplen to `bytes`")
	pcapTimeout = flag.Int("pcap-timeout", 0,
		"set pcap timeout to `milliseconds`")
	pcapMaxPkts = flag.Int("pcap-maxpkts", 0, "set maximum packets to "+
		"capture to `number` (may require pcap-timeout argument)")
	pcapMaxTime = flag.Int("pcap-maxtime", 0, "set maximum capturing "+
		"time to `seconds` (may require pcap-timeout argument)")
	pcapFilter = flag.String("pcap-filter", "",
		"set pcap packet filter to `filter` (e.g.: \"not port 22\")")

	// display variables
	showReserved = flag.Bool("show-reserved", false,
		"print reserved values in messages")
	showTimestamps = flag.Bool("show-timestamps", true, "print timestamps")
	showDumps      = flag.Bool("show-hex", false,
		"print message hex dumps")

	// output, changed by http output
	stdout     io.Writer = os.Stdout
	stderr     io.Writer = os.Stderr
	httpListen           = flag.String("http", "", "use http server "+
		"output and listen on `address` "+
		"(e.g.: :8000 or 127.0.0.1:8080)")
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
