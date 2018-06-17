package dns

import (
	"github.com/google/gopacket/layers"
	"github.com/untangle/packetd/services/dispatch"
	"github.com/untangle/packetd/services/logger"
	"sync"
)

var appname = "dns"

//-----------------------------------------------------------------------------

// PluginStartup function is called to allow plugin specific initialization. We
// increment the argumented WaitGroup so the main process can wait for
// our shutdown function to return during shutdown.
func PluginStartup(childsync *sync.WaitGroup) {
	logger.LogMessage(logger.LogInfo, appname, "PluginStartup(%s) has been called\n", appname)
	dispatch.InsertNfqueueSubscription(appname, 1, PluginNfqueueHandler)
	childsync.Add(1)
}

//-----------------------------------------------------------------------------

// PluginShutdown function called when the daemon is shutting down. We call Done
// for the argumented WaitGroup to let the main process know we're finished.
func PluginShutdown(childsync *sync.WaitGroup) {
	logger.LogMessage(logger.LogInfo, appname, "PluginShutdown(%s) has been called\n", appname)
	childsync.Done()
}

//-----------------------------------------------------------------------------

// PluginNfqueueHandler is called to handle nfqueue packet data. We only
// look at DNS packets, extracting the QNAME and putting it in conndict.
func PluginNfqueueHandler(ch chan<- dispatch.SubscriptionResult, mess dispatch.TrafficMessage, ctid uint) {
	var result dispatch.SubscriptionResult
	result.Owner = appname
	result.SessionRelease = true
	result.PacketMark = 0

	// get the DNS layer
	dnsLayer := mess.Packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		ch <- result
		return
	}

	dns := dnsLayer.(*layers.DNS)

	if dns.QDCount < 1 {
		ch <- result
		return
	}

	query := dns.Questions[0]
	logger.LogMessage(logger.LogInfo, appname, "DNS QUERY DETECTED NAME:%s TYPE:%d CLASS:%d\n", query.Name, query.Type, query.Class)

	// use the channel to return our result
	ch <- result
}

//-----------------------------------------------------------------------------
