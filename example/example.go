package example

import (
	"encoding/hex"
	"github.com/untangle/packetd/support"
	"sync"
)

var appname = "example"

//-----------------------------------------------------------------------------

// PluginStartup function is called to allow plugin specific initialization. We
// increment the argumented WaitGroup so the main process can wait for
// our goodbye function to return during shutdown.
func PluginStartup(childsync *sync.WaitGroup) {
	support.LogMessage(support.LogInfo, appname, "PluginStartup(%s) has been called\n", "example")
	support.InsertNetfilterSubscription(appname, 1, PluginNetfilterHandler)
	childsync.Add(1)
}

//-----------------------------------------------------------------------------

// PluginGoodbye function called when the daemon is shutting down. We call Done
// for the argumented WaitGroup to let the main process know we're finished.
func PluginGoodbye(childsync *sync.WaitGroup) {
	support.LogMessage(support.LogInfo, appname, "PluginGoodbye(%s) has been called\n", "example")
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
	support.LogMessage(support.LogDebug, appname, "NetfilterHandler recived %d BYTES from %s to %s\n%s\n", mess.MsgLength, mess.MsgIP.SrcIP, mess.MsgIP.DstIP, hex.Dump(mess.MsgPacket.Data()))

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

// PluginNetloggerHandler receives NFLOG events.
func PluginNetloggerHandler(logger *support.NetloggerMessage) {
	support.LogMessage(support.LogDebug, appname, "NetloggerHandler PROTO:%d ICMP:%d SIF:%d DIF:%d SADR:%s DADR:%s SPORT:%d DPORT:%d MARK:%X PREFIX:%s\n",
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
