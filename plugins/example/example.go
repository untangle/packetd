package example

import (
	"encoding/hex"
	"github.com/untangle/packetd/services/dispatch"
	"github.com/untangle/packetd/services/logger"
)

var logsrc = "example"

// PluginStartup function is called to allow plugin specific initialization. We
// increment the argumented WaitGroup so the main process can wait for
// our shutdown function to return during shutdown.
func PluginStartup() {
	logger.LogMessage(logger.LogInfo, logsrc, "PluginStartup(%s) has been called\n", logsrc)
	dispatch.InsertNfqueueSubscription(logsrc, 2, PluginNfqueueHandler)
	dispatch.InsertConntrackSubscription(logsrc, 2, PluginConntrackHandler)
	dispatch.InsertNetloggerSubscription(logsrc, 2, PluginNetloggerHandler)
}

// PluginShutdown function called when the daemon is shutting down. We call Done
// for the argumented WaitGroup to let the main process know we're finished.
func PluginShutdown() {
	logger.LogMessage(logger.LogInfo, logsrc, "PluginShutdown(%s) has been called\n", logsrc)
}

// PluginNfqueueHandler receives a TrafficMessage which includes a Tuple and
// a gopacket.Packet, along with the IP and TCP or UDP layer already extracted.
// We do whatever we like with the data, and when finished, we return an
// integer via the argumented channel with any bits set that we want added to
// the packet mark.
func PluginNfqueueHandler(mess dispatch.TrafficMessage, ctid uint, newSession bool) dispatch.NfqueueResult {
	// our example simply dumps the raw message to the console
	logger.LogMessage(logger.LogDebug, logsrc, "NfqueueHandler received %d BYTES from %s to %s\n%s\n", mess.Length, mess.IPlayer.SrcIP, mess.IPlayer.DstIP, hex.Dump(mess.Packet.Data()))

	var result dispatch.NfqueueResult
	result.Owner = logsrc
	result.SessionRelease = true
	result.PacketMark = 0

	return result
}

// PluginConntrackHandler receives conntrack dispatch. The message will be one
// of three possible values: N, U, or D for new entry, an update to an existing
// entry, or delete of an existing entry.
func PluginConntrackHandler(message int, entry *dispatch.ConntrackEntry) {
	logger.LogMessage(logger.LogDebug, logsrc, "ConntrackHandler MSG:%c ID:%d PROTO:%d SADDR:%s SPORT:%d DADDR:%s DPORT:%d TX:%d RX:%d UC:%d\n",
		message,
		entry.ConntrackID,
		entry.ClientSideTuple.Protocol,
		entry.ClientSideTuple.ClientAddr,
		entry.ClientSideTuple.ClientPort,
		entry.ClientSideTuple.ServerAddr,
		entry.ClientSideTuple.ServerPort,
		entry.C2Sbytes,
		entry.S2Cbytes,
		entry.EventCount)
}

// PluginNetloggerHandler receives NFLOG dispatch.
func PluginNetloggerHandler(netlogger *dispatch.NetloggerMessage) {
	logger.LogMessage(logger.LogDebug, logsrc, "NetloggerHandler PROTO:%d ICMP:%d SIF:%d DIF:%d SADR:%s DADR:%s SPORT:%d DPORT:%d MARK:%X PREFIX:%s\n",
		netlogger.Protocol,
		netlogger.IcmpType,
		netlogger.SrcIntf,
		netlogger.DstIntf,
		netlogger.SrcAddr,
		netlogger.DstAddr,
		netlogger.SrcPort,
		netlogger.DstPort,
		netlogger.Mark,
		netlogger.Prefix)
}
