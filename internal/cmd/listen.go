package cmd

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"

	"github.com/hwipl/smc-go/pkg/clc"
)

type PcapHandler interface {
	HandlePacket(gopacket.Packet)
	HandleTimer()
}

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

type PcapListener struct {
	pcapHandle *pcap.Handle

	Handler PcapHandler

	File    string
	Device  string
	Promisc bool
	Snaplen int
	Timeout time.Duration
	Filter  string
	MaxPkts int
	MaxTime time.Duration
}

// getFirstPcapInterface sets the first network interface found by pcap
func (p *PcapListener) getFirstPcapInterface() {
	ifs, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	if len(ifs) > 0 {
		p.Device = ifs[0].Name
		return
	}
	log.Fatal("No network interface found")
}

// Prepare prepares the pcap listener for the listen function
func (p *PcapListener) Prepare() {
	// open pcap handle
	var pcapErr error
	var startText string
	if *pcapFile == "" {
		// set pcap timeout
		timeout := pcap.BlockForever
		if p.Timeout > 0 {
			timeout = p.Timeout
		}

		// set interface
		if p.Device == "" {
			p.getFirstPcapInterface()
		}

		// open device
		p.pcapHandle, pcapErr = pcap.OpenLive(p.Device,
			int32(p.Snaplen), p.Promisc, timeout)
		startText = fmt.Sprintf("Listening on interface %s:\n",
			p.Device)
	} else {
		// open pcap file
		p.pcapHandle, pcapErr = pcap.OpenOffline(p.File)
		startText = fmt.Sprintf("Reading packets from file %s:\n",
			p.File)
	}
	if pcapErr != nil {
		log.Fatal(pcapErr)
	}
	if *pcapFilter != "" {
		if err := p.pcapHandle.SetBPFFilter(*pcapFilter); err != nil {
			log.Fatal(pcapErr)
		}
	}
	fmt.Fprintf(stdout, startText)
}

// Loop implements the listen loop for the listen function
func (p *PcapListener) Loop() {
	defer p.pcapHandle.Close()

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(p.pcapHandle,
		p.pcapHandle.LinkType())
	packets := packetSource.Packets()

	// setup timer
	ticker := time.Tick(time.Minute)

	// set stop time if configured
	stop := make(<-chan time.Time)
	if p.MaxTime > 0 {
		stop = time.After(p.MaxTime)
	}

	// handle packets and timer events
	count := 0
	for {
		select {
		case packet := <-packets:
			if packet == nil {
				return
			}
			p.Handler.HandlePacket(packet)
			count++
			if p.MaxPkts > 0 && count == p.MaxPkts {
				return
			}
		case <-ticker:
			p.Handler.HandleTimer()
		case <-stop:
			return
		}
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
	listener := PcapListener{
		Handler: &handler,
		File:    *pcapFile,
		Device:  *pcapDevice,
		Promisc: *pcapPromisc,
		Snaplen: *pcapSnaplen,
		Timeout: time.Duration(*pcapTimeout) * time.Millisecond,
		Filter:  *pcapFilter,
		MaxPkts: *pcapMaxPkts,
		MaxTime: time.Duration(*pcapMaxTime) * time.Second,
	}

	// start listen loop
	listener.Prepare()
	listener.Loop()
}
