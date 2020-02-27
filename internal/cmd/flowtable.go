package cmd

import (
	"sync"

	"github.com/google/gopacket"
)

var (
	// flow table
	flows flowTable
)

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
