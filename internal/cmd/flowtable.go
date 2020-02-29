package cmd

import (
	"sync"

	"github.com/google/gopacket"
)

var (
	// flows stores the flow table
	flows flowTable
)

// flowTable stores a flow table protected by a mutex
type flowTable struct {
	lock sync.Mutex
	fmap map[gopacket.Flow]map[gopacket.Flow]bool
}

// init initializes the flow table
func (ft *flowTable) init() {
	ft.lock.Lock()
	if ft.fmap == nil {
		ft.fmap = make(map[gopacket.Flow]map[gopacket.Flow]bool)
	}
	ft.lock.Unlock()
}

// add adds an entry identified by the network flow net and the transport flow
// trans  to the flow table
func (ft *flowTable) add(net, trans gopacket.Flow) {
	ft.lock.Lock()
	if ft.fmap[net] == nil {
		ft.fmap[net] = make(map[gopacket.Flow]bool)
	}

	ft.fmap[net][trans] = true
	ft.lock.Unlock()
}

// del removes the entry identified by the network flow net and the tansport
// flow trans from the flow table
func (ft *flowTable) del(net, trans gopacket.Flow) {
	ft.lock.Lock()
	if ft.fmap[net] != nil {
		delete(ft.fmap[net], trans)
	}
	ft.lock.Unlock()
}

// get returns the entry identified by the network flow net and the transport
// flow trans from the flow table
func (ft *flowTable) get(net, trans gopacket.Flow) bool {
	check := false

	ft.lock.Lock()
	if ft.fmap[net] != nil {
		check = ft.fmap[net][trans]
	}
	ft.lock.Unlock()

	return check
}
