package cmd

import (
	"io"
	"log"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/tcpassembly"
	"github.com/gopacket/gopacket/tcpassembly/tcpreader"
	"github.com/hwipl/smc-go/pkg/clc"
)

const (
	// CLC message buffer size for 2 CLC messages per flow/direction
	clcMessageBufSize = clc.MaxMessageSize * 2
)

// smcStream is used for decoding smc packets
type smcStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
}

// run parses the smc stream
func (s *smcStream) run() {
	var clcMsg clc.Message
	var clcLen uint16
	buf := make([]byte, clcMessageBufSize)
	// get at least enough bytes for the CLC header
	skip := clc.HeaderLen
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
			printCLC(s.net, s.transport, clcMsg)

			// wait for next handshake message
			clcMsg = nil
			clcLen = 0
			skip += clc.HeaderLen
			continue

		}

		// if there is not enough data left in buffer, we are done
		if total < skip {
			break
		}

		// parse header of current CLC message
		clcMsg, clcLen =
			clc.NewMessage(buf[skip-clc.HeaderLen:])
		if clcMsg == nil {
			break
		}

		// skip to end of current message to be able to parse it
		skip += int(clcLen) - clc.HeaderLen
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

// smcStreamFactory implements tcpassembly.StreamFactory
type smcStreamFactory struct{}

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
