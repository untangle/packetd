package example

import "fmt"
import "sync"
import "encoding/hex"
import "github.com/untangle/packetd/support"
import "github.com/google/gopacket"
import "github.com/google/gopacket/layers"

/*---------------------------------------------------------------------------*/
func Plugin_Startup(childsync *sync.WaitGroup) {
	support.LogMessage("Plugin_Startup(%s) has been called\n", "example")
	childsync.Add(1)
}

/*---------------------------------------------------------------------------*/
func Plugin_Goodbye(childsync *sync.WaitGroup) {
	support.LogMessage("Plugin_Goodbye(%s) has been called\n", "example")
	childsync.Done()
}

/*---------------------------------------------------------------------------*/
func Plugin_netfilter_handler(ch chan<- int32,buffer []byte, length int) {
	packet := gopacket.NewPacket(buffer, layers.LayerTypeIPv4, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if (ipLayer != nil) {
		addr := ipLayer.(*layers.IPv4)
		fmt.Printf("NETFILTER %d BYTES FROM %s\n%s\n",length, addr.SrcIP, hex.Dump(buffer))
	}

	// use the channel to return our mark bits
	ch <- 1
}

/*---------------------------------------------------------------------------*/
func Plugin_conntrack_handler(message int, entry *support.ConntrackEntry) {
	fmt.Printf("CONNTRACK MSG:%c PROTO:%d SADDR:%s SPORT:%d DADDR:%s DPORT:%d TX:%d RX:%d UC:%d\n",
		message,
		entry.SessionTuple.Protocol,
		entry.SessionTuple.ClientAddr,
		entry.SessionTuple.ClientPort,
		entry.SessionTuple.ServerAddr,
		entry.SessionTuple.ServerPort,
		entry.C2Sbytes,
		entry.S2Cbytes,
		entry.UpdateCount)
}

/*---------------------------------------------------------------------------*/
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
