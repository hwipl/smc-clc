package cmd

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/hwipl/smc-clc/internal/messages"
)

// handlePacket handles a packet
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

// handleTimer handles a timer event
func handleTimer(assembler *tcpassembly.Assembler) {
	flushedFmt := "Timer: flushed %d, closed %d connections\n"

	// flush connections without activity in the past minute
	flushed, closed := assembler.FlushOlderThan(time.Now().Add(
		-time.Minute))
	if flushed > 0 {
		fmt.Fprintf(stdout, flushedFmt, flushed, closed)
	}
}

// listen listens on the network interface and parses packets
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
