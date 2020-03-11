package cmd

import (
	"fmt"
	"io"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"github.com/hwipl/smc-clc/internal/clc"
)

const (
	// CLC message buffer size for 2 CLC messages per flow/direction
	clcMessageBufSize = clc.CLCMessageMaxSize * 2
)

// smcStreamFactory implements tcpassembly.StreamFactory
type smcStreamFactory struct{}

// smcStream is used for decoding smc packets
type smcStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
}

// New creates a new smc stream factory (-> implement
// tcpassembly.StreamFactory)
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

// printCLC prints the info of stream
func printCLC(s *smcStream, clc clc.Message) {
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

// run parses the smc stream
func (s *smcStream) run() {
	var clcMsg clc.Message
	var clcLen uint16
	buf := make([]byte, clcMessageBufSize)
	// get at least enough bytes for the CLC header
	skip := clc.CLCHeaderLen
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
		if clcMsg != nil {
			// parse and print message
			clcMsg.Parse(buf[skip-int(clcLen) : skip])
			printCLC(s, clcMsg)

			// wait for next handshake message
			clcMsg = nil
			clcLen = 0
			skip += clc.CLCHeaderLen
			continue

		}

		// if there is not enough data left in buffer, we are done
		if total < skip {
			break
		}

		// parse header of current CLC message
		clcMsg, clcLen =
			clc.NewMessage(buf[skip-clc.CLCHeaderLen:])
		if clcMsg == nil {
			break
		}

		// skip to end of current message to be able to parse it
		skip += int(clcLen) - clc.CLCHeaderLen
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
