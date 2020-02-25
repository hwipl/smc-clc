package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"

	"github.com/hwipl/smc-clc/internal/messages"
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

	// flow table
	flows flowTable

	// output, changed by http output
	stdout     io.Writer = os.Stdout
	stderr     io.Writer = os.Stderr
	httpBuffer buffer
	httpListen = flag.String("http", "",
		"use http server and set listen address (e.g.: :8000)")
)

const (
	// CLC message buffer size for 2 CLC messages per flow/direction
	clcMessageBufSize = messages.CLCMessageMaxSize * 2
)

// buffer is a bytes.Buffer protected by a mutex
type buffer struct {
	lock   sync.Mutex
	buffer bytes.Buffer
}

// Write writes p to the buffer
func (b *buffer) Write(p []byte) (n int, err error) {
	b.lock.Lock()
	defer b.lock.Unlock()
	return b.buffer.Write(p)
}

// copyBuffer copies the underlying bytes.Buffer and returns it
func (b *buffer) copyBuffer() *bytes.Buffer {
	b.lock.Lock()
	defer b.lock.Unlock()
	oldBuf := b.buffer.Bytes()
	newBuf := make([]byte, len(oldBuf))
	copy(newBuf, oldBuf)
	return bytes.NewBuffer(newBuf)
}

// flow table
type flowTable struct {
	lock sync.Mutex
	fmap map[gopacket.Flow]map[gopacket.Flow]bool
}

// init flow table
func (ft *flowTable) init() {
	ft.lock.Lock()
	if ft.fmap == nil {
		ft.fmap = make(map[gopacket.Flow]map[gopacket.Flow]bool)
	}
	ft.lock.Unlock()
}

// add entry to flow table
func (ft *flowTable) add(net, trans gopacket.Flow) {
	ft.lock.Lock()
	if ft.fmap[net] == nil {
		ft.fmap[net] = make(map[gopacket.Flow]bool)
	}

	ft.fmap[net][trans] = true
	ft.lock.Unlock()
}

// remove entry from flow table
func (ft *flowTable) del(net, trans gopacket.Flow) {
	ft.lock.Lock()
	if ft.fmap[net] != nil {
		delete(ft.fmap[net], trans)
	}
	ft.lock.Unlock()
}

// get entry from flow table
func (ft *flowTable) get(net, trans gopacket.Flow) bool {
	check := false

	ft.lock.Lock()
	if ft.fmap[net] != nil {
		check = ft.fmap[net][trans]
	}
	ft.lock.Unlock()

	return check
}

// smcStreamFactory implementing tcpassembly.StreamFactory
type smcStreamFactory struct{}

// smcStream for decoding of smc packets
type smcStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
}

// create new smc stream factory (-> implement tcpassembly.StreamFactory)
func (h *smcStreamFactory) New(
	net, transport gopacket.Flow) tcpassembly.Stream {
	sstream := &smcStream{
		net:       net,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
	}
	go sstream.run() // parse stream in goroutine

	// ReaderStream implements tcpassembly.Stream, so we can return a
	// pointer to it.
	return &sstream.r
}

// print CLC info of stream
func printCLC(s *smcStream, clc *messages.CLCMessage) {
	clcFmt := "%s%s:%s -> %s:%s: %s\n"
	t := ""

	if *showTimestamps {
		t = time.Now().Format("15:04:05.000000 ")
	}
	if *showReserved {
		fmt.Fprintf(stdout, clcFmt, t, s.net.Src(), s.transport.Src(),
			s.net.Dst(), s.transport.Dst(), clc.Reserved())
	} else {
		fmt.Fprintf(stdout, clcFmt, t, s.net.Src(), s.transport.Src(),
			s.net.Dst(), s.transport.Dst(), clc)
	}
	if *showDumps {
		fmt.Fprintf(stdout, "%s", clc.Dump())
	}
}

// parse smc stream
func (s *smcStream) run() {
	var clc *messages.CLCMessage
	buf := make([]byte, clcMessageBufSize)
	// get at least enough bytes for the CLC header
	skip := messages.CLCHeaderLen
	eof := false
	total := 0

	for {
		// try to read enough data into buffer and check EOF and errors
		for total < skip && !eof {
			n, err := s.r.Read(buf[total:])
			if err != nil {
				if err != io.EOF {
					log.Println("Error reading stream:",
						err)
				}
				eof = true
			}
			total += n
		}

		// parse and print current CLC message
		if clc != nil {
			// parse and print message
			clc.Parse(buf[skip-int(clc.Length) : skip])
			printCLC(s, clc)

			// wait for next handshake message
			clc = nil
			skip += messages.CLCHeaderLen
			continue

		}

		// if there is not enough data left in buffer, we are done
		if total < skip {
			break
		}

		// parse header of current CLC message
		clc = messages.ParseCLCHeader(buf[skip-messages.CLCHeaderLen:])
		if clc == nil {
			break
		}

		// skip to end of current message to be able to parse it
		skip += int(clc.Length) - messages.CLCHeaderLen
	}

	// discard everything
	tcpreader.DiscardBytesToEOF(&s.r)
}

// ReassemblyComplete is called when the TCP assembler believes the stream has
// finished
func (s *smcStream) ReassemblyComplete() {
	// remove entry from flow table
	flows.del(s.net, s.transport)
}

// handle packet
func handlePacket(assembler *tcpassembly.Assembler, packet gopacket.Packet) {
	// only handle tcp packets (with valid network layer)
	if packet.NetworkLayer() == nil ||
		packet.TransportLayer() == nil ||
		packet.TransportLayer().LayerType() !=
			layers.LayerTypeTCP {
		return
	}
	tcp, ok := packet.TransportLayer().(*layers.TCP)
	if !ok {
		log.Fatal("Error parsing TCP packet")
	}

	// if smc option is set, try to parse tcp stream
	nflow := packet.NetworkLayer().NetworkFlow()
	tflow := packet.TransportLayer().TransportFlow()
	if messages.CheckSMCOption(tcp) || flows.get(nflow, tflow) {
		flows.add(nflow, tflow)
		assembler.AssembleWithTimestamp(nflow, tcp,
			packet.Metadata().Timestamp)
	}
}

// handle timer event
func handleTimer(assembler *tcpassembly.Assembler) {
	flushedFmt := "Timer: flushed %d, closed %d connections\n"

	// flush connections without activity in the past minute
	flushed, closed := assembler.FlushOlderThan(time.Now().Add(
		-time.Minute))
	if flushed > 0 {
		fmt.Fprintf(stdout, flushedFmt, flushed, closed)
	}
}

// listen on network interface and parse packets
func listen() {
	// open device
	pcapHandle, pcapErr := pcap.OpenLive(*pcapDevice, int32(*pcapSnaplen),
		*pcapPromisc, pcap.BlockForever)
	if pcapErr != nil {
		log.Fatal(pcapErr)
	}
	defer pcapHandle.Close()

	// Set up assembly
	streamFactory := &smcStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	// init flow table
	flows.init()

	// Use the handle as a packet source to process all packets
	fmt.Fprintf(stdout, "Starting to listen on interface %s.\n",
		*pcapDevice)
	packetSource := gopacket.NewPacketSource(pcapHandle,
		pcapHandle.LinkType())
	packets := packetSource.Packets()

	// setup timer
	ticker := time.Tick(time.Minute)

	// handle packets and timer events
	for {
		select {
		case packet := <-packets:
			handlePacket(assembler, packet)
		case <-ticker:
			handleTimer(assembler)
		}
	}
}

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

// main
func main() {
	flag.Parse()
	if *httpListen != "" {
		setHttpOutput()
	}
	log.SetOutput(stderr)
	listen()
}
