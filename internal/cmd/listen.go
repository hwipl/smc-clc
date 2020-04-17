package cmd

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"

	"github.com/hwipl/smc-go/pkg/clc"
	"github.com/hwipl/smc-go/pkg/pcap"
)

type handler struct {
	assembler *tcpassembly.Assembler
}

// handlePacket handles a packet
func (h *handler) HandlePacket(packet gopacket.Packet) {
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
	if clc.CheckSMCOption(tcp) || flows.get(nflow, tflow) {
		flows.add(nflow, tflow)
		h.assembler.AssembleWithTimestamp(nflow, tcp,
			packet.Metadata().Timestamp)
	}
}

// handleTimer handles a timer event
func (h *handler) HandleTimer() {
	flushedFmt := "Timer: flushed %d, closed %d connections\n"

	// flush connections without activity in the past minute
	flushed, closed := h.assembler.FlushOlderThan(time.Now().Add(
		-time.Minute))
	if flushed > 0 {
		fmt.Fprintf(stdout, flushedFmt, flushed, closed)
	}
}

// listen listens on the network interface and parses packets
func listen() {
	// Set up assembly
	streamFactory := &smcStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	// init flow table
	flows.init()

	// create handler
	var handler handler
	handler.assembler = assembler

	// create listener
	listener := pcap.Listener{
		PacketHandler: &handler,
		TimerHandler:  &handler,
		Timer:         time.Minute,
		File:          *pcapFile,
		Device:        *pcapDevice,
		Promisc:       *pcapPromisc,
		Snaplen:       *pcapSnaplen,
		Timeout:       time.Duration(*pcapTimeout) * time.Millisecond,
		Filter:        *pcapFilter,
		MaxPkts:       *pcapMaxPkts,
		MaxTime:       time.Duration(*pcapMaxTime) * time.Second,
	}

	// start listen loop
	listener.Prepare()
	listener.Loop()
}
