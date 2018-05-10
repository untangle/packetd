package example

import (
	"encoding/hex"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/untangle/packetd/support"
	"sync"
)

//-----------------------------------------------------------------------------

// Startup function called to allow plugin specific initialization. We
// increment the argumented WaitGroup so the main process can wait for
// our goodbye function to return during shutdown.
func Plugin_Startup(childsync *sync.WaitGroup) {
	support.LogMessage("Plugin_Startup(%s) has been called\n", "example")
	childsync.Add(1)
}

//-----------------------------------------------------------------------------

// Goodbye function called when the daemon is shutting down. We call Done
// for the argumented WaitGroup to let the main process know we're finished.
func Plugin_Goodbye(childsync *sync.WaitGroup) {
	support.LogMessage("Plugin_Goodbye(%s) has been called\n", "example")
	childsync.Done()
}

//-----------------------------------------------------------------------------

// Our handler for receiving raw netfilter packet data. We can do whatever we
// like with the data, and when finished, we return an integer via the
// argumented channel with any bits set that we want added to the packet mark.
func Plugin_netfilter_handler(ch chan<- int32, buffer []byte, length int, ctid uint) {
	packet := gopacket.NewPacket(buffer, layers.LayerTypeIPv4, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		addr := ipLayer.(*layers.IPv4)
		fmt.Printf("NETFILTER %d BYTES FROM %s\n%s\n", length, addr.SrcIP, hex.Dump(buffer))
	}

	// use the channel to return our mark bits
	ch <- 1
}

//-----------------------------------------------------------------------------

// Our handler for receiving conntrack events. The message will be one of
// three possible values: N, U, or D for new entry, an update to an existing
// entry, or delete of an existing entry.
func Plugin_conntrack_handler(message int, entry *support.ConntrackEntry) {
	fmt.Printf("CONNTRACK MSG:%c ID:%d PROTO:%d SADDR:%s SPORT:%d DADDR:%s DPORT:%d TX:%d RX:%d UC:%d\n",
		message,
		entry.ConntrackId,
		entry.SessionTuple.Protocol,
		entry.SessionTuple.ClientAddr,
		entry.SessionTuple.ClientPort,
		entry.SessionTuple.ServerAddr,
		entry.SessionTuple.ServerPort,
		entry.C2Sbytes,
		entry.S2Cbytes,
		entry.UpdateCount)
}

//-----------------------------------------------------------------------------

// Our handler for receiving NFLOG events.
func Plugin_netlogger_handler(logger *support.Logger) {
	fmt.Printf("NETLOGGER PROTO:%d ICMP:%d SIF:%d DIF:%d SADR:%s DADR:%s SPORT:%d DPORT:%d MARK:%X PREFIX:%s\n",
		logger.Protocol,
		logger.IcmpType,
		logger.SrcIntf,
		logger.DstIntf,
		support.Int2Ip(logger.SrcAddr),
		support.Int2Ip(logger.DstAddr),
		logger.SrcPort,
		logger.DstPort,
		logger.Mark,
		logger.Prefix)
}

/*---------------------------------------------------------------------------*/
