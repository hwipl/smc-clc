package cmd

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/hwipl/smc-go/pkg/clc"
)

// printCLC prints the CLC message
func printCLC(net, transport gopacket.Flow, clc clc.Message) {
	clcFmt := "%s%s:%s -> %s:%s: %s\n"
	t := ""

	if *showTimestamps {
		t = time.Now().Format("15:04:05.000000 ")
	}
	if *showReserved {
		fmt.Fprintf(stdout, clcFmt, t, net.Src(), transport.Src(),
			net.Dst(), transport.Dst(), clc.Reserved())
	} else {
		fmt.Fprintf(stdout, clcFmt, t, net.Src(), transport.Src(),
			net.Dst(), transport.Dst(), clc)
	}
	if *showDumps {
		fmt.Fprintf(stdout, "%s", clc.Dump())
	}
}
