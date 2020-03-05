package cmd

import (
	"fmt"
	"io"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"github.com/hwipl/smc-clc/internal/messages"
)

const (
	// CLC message buffer size for 2 CLC messages per flow/direction
	clcMessageBufSize = messages.CLCMessageMaxSize * 2
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
func printCLC(s *smcStream, clc messages.Message) {
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
	var clc messages.Message
	var clcLen uint16
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
			clc.Parse(buf[skip-int(clcLen) : skip])
			printCLC(s, clc)

			// wait for next handshake message
			clc = nil
			clcLen = 0
			skip += messages.CLCHeaderLen
			continue

		}

		// if there is not enough data left in buffer, we are done
		if total < skip {
			break
		}

		// parse header of current CLC message
		clc, clcLen =
			messages.NewMessage(buf[skip-messages.CLCHeaderLen:])
		if clc == nil {
			break
		}

		// skip to end of current message to be able to parse it
		skip += int(clcLen) - messages.CLCHeaderLen
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
