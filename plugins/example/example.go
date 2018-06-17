package example

import (
	"encoding/hex"
	"github.com/untangle/packetd/services/support"
	"sync"
)

var appname = "example"

//-----------------------------------------------------------------------------

// PluginStartup function is called to allow plugin specific initialization. We
// increment the argumented WaitGroup so the main process can wait for
// our shutdown function to return during shutdown.
func PluginStartup(childsync *sync.WaitGroup) {
	support.LogMessage(support.LogInfo, appname, "PluginStartup(%s) has been called\n", appname)
	support.InsertNetfilterSubscription(appname, 1, PluginNetfilterHandler)
	support.InsertConntrackSubscription(appname, 1, PluginConntrackHandler)
	support.InsertNetloggerSubscription(appname, 1, PluginNetloggerHandler)
	childsync.Add(1)
}

//-----------------------------------------------------------------------------

// PluginShutdown function called when the daemon is shutting down. We call Done
// for the argumented WaitGroup to let the main process know we're finished.
func PluginShutdown(childsync *sync.WaitGroup) {
	support.LogMessage(support.LogInfo, appname, "PluginShutdown(%s) has been called\n", appname)
	childsync.Done()
}

//-----------------------------------------------------------------------------

// PluginNetfilterHandler receives a TrafficMessage which includes a Tuple and
// a gopacket.Packet, along with the IP and TCP or UDP layer already extracted.
// We do whatever we like with the data, and when finished, we return an
// integer via the argumented channel with any bits set that we want added to
// the packet mark.
func PluginNetfilterHandler(ch chan<- support.SubscriptionResult, mess support.TrafficMessage, ctid uint) {
	// our example simply dumps the raw message to the console
	support.LogMessage(support.LogDebug, appname, "NetfilterHandler recived %d BYTES from %s to %s\n%s\n", mess.Length, mess.IPlayer.SrcIP, mess.IPlayer.DstIP, hex.Dump(mess.Packet.Data()))

	var result support.SubscriptionResult
	result.Owner = appname
	result.SessionRelease = true
	result.PacketMark = 0

	// use the channel to return our result
	ch <- result
}

//-----------------------------------------------------------------------------

// PluginConntrackHandler receives conntrack events. The message will be one
// of three possible values: N, U, or D for new entry, an update to an existing
// entry, or delete of an existing entry.
func PluginConntrackHandler(message int, entry *support.ConntrackEntry) {
	support.LogMessage(support.LogDebug, appname, "ConntrackHandler MSG:%c ID:%d PROTO:%d SADDR:%s SPORT:%d DADDR:%s DPORT:%d TX:%d RX:%d UC:%d\n",
		message,
		entry.ConntrackID,
		entry.ClientSideTuple.Protocol,
		entry.ClientSideTuple.ClientAddr,
		entry.ClientSideTuple.ClientPort,
		entry.ClientSideTuple.ServerAddr,
		entry.ClientSideTuple.ServerPort,
		entry.C2Sbytes,
		entry.S2Cbytes,
		entry.UpdateCount)
}

//-----------------------------------------------------------------------------

// PluginNetloggerHandler receives NFLOG events.
func PluginNetloggerHandler(logger *support.NetloggerMessage) {
	support.LogMessage(support.LogDebug, appname, "NetloggerHandler PROTO:%d ICMP:%d SIF:%d DIF:%d SADR:%s DADR:%s SPORT:%d DPORT:%d MARK:%X PREFIX:%s\n",
		logger.Protocol,
		logger.IcmpType,
		logger.SrcIntf,
		logger.DstIntf,
		logger.SrcAddr,
		logger.DstAddr,
		logger.SrcPort,
		logger.DstPort,
		logger.Mark,
		logger.Prefix)
}

/*---------------------------------------------------------------------------*/
