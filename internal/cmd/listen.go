package cmd

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/hwipl/smc-clc/internal/clc"
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
	if clc.CheckSMCOption(tcp) || flows.get(nflow, tflow) {
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

// listenPrepare prepares the assembler and pcap handle for the listen function
func listenPrepare() (*tcpassembly.Assembler, *pcap.Handle) {
	// open pcap handle
	var pcapHandle *pcap.Handle
	var pcapErr error
	var startText string
	if *pcapFile == "" {
		// set pcap timeout
		timeout := pcap.BlockForever
		if *pcapTimeout > 0 {
			timeout = time.Duration(*pcapTimeout) *
				time.Millisecond
		}

		// open device
		pcapHandle, pcapErr = pcap.OpenLive(*pcapDevice,
			int32(*pcapSnaplen), *pcapPromisc, timeout)
		startText = fmt.Sprintf("Listening on interface %s:\n",
			*pcapDevice)
	} else {
		// open pcap file
		pcapHandle, pcapErr = pcap.OpenOffline(*pcapFile)
		startText = fmt.Sprintf("Reading packets from file %s:\n",
			*pcapFile)
	}
	if pcapErr != nil {
		log.Fatal(pcapErr)
	}
	if *pcapFilter != "" {
		if err := pcapHandle.SetBPFFilter(*pcapFilter); err != nil {
			log.Fatal(pcapErr)
		}
	}
	fmt.Fprintf(stdout, startText)

	// Set up assembly
	streamFactory := &smcStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	// init flow table
	flows.init()

	return assembler, pcapHandle
}

// listenLoop implements the listen loop for the listen function
func listenLoop(assembler *tcpassembly.Assembler, pcapHandle *pcap.Handle) {
	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(pcapHandle,
		pcapHandle.LinkType())
	packets := packetSource.Packets()

	// setup timer
	ticker := time.Tick(time.Minute)

	// handle packets and timer events
	count := 0
	for {
		select {
		case packet := <-packets:
			if packet == nil {
				return
			}
			handlePacket(assembler, packet)
			count++
			if *pcapMaxPkts > 0 && count == *pcapMaxPkts {
				return
			}
		case <-ticker:
			handleTimer(assembler)
		}
	}

}

// listen listens on the network interface and parses packets
func listen() {
	// get assembler and pcap handle
	assembler, pcapHandle := listenPrepare()
	defer pcapHandle.Close()

	// start listen loop
	listenLoop(assembler, pcapHandle)
}
