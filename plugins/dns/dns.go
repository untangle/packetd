package dns

import (
	"github.com/google/gopacket/layers"
	"github.com/untangle/packetd/services/support"
	"sync"
)

var appname = "dns"

//-----------------------------------------------------------------------------

// PluginStartup function is called to allow plugin specific initialization. We
// increment the argumented WaitGroup so the main process can wait for
// our goodbye function to return during shutdown.
func PluginStartup(childsync *sync.WaitGroup) {
	support.LogMessage(support.LogInfo, appname, "PluginStartup(%s) has been called\n", appname)
	support.InsertNetfilterSubscription(appname, 1, PluginNetfilterHandler)
	childsync.Add(1)
}

//-----------------------------------------------------------------------------

// PluginGoodbye function called when the daemon is shutting down. We call Done
// for the argumented WaitGroup to let the main process know we're finished.
func PluginGoodbye(childsync *sync.WaitGroup) {
	support.LogMessage(support.LogInfo, appname, "PluginGoodbye(%s) has been called\n", appname)
	childsync.Done()
}

//-----------------------------------------------------------------------------

// PluginNetfilterHandler is called to handle netfilter packet data. We only
// look at DNS packets, extracting the QNAME and putting it in conndict.
func PluginNetfilterHandler(ch chan<- support.SubscriptionResult, mess support.TrafficMessage, ctid uint) {
	var result support.SubscriptionResult
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
	support.LogMessage(support.LogInfo, appname, "DNS QUERY DETECTED NAME:%s TYPE:%d CLASS:%d\n", query.Name, query.Type, query.Class)

	// use the channel to return our result
	ch <- result
}

//-----------------------------------------------------------------------------
