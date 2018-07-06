package dns

import (
	"github.com/google/gopacket/layers"
	"github.com/untangle/packetd/services/dispatch"
	"github.com/untangle/packetd/services/logger"
)

// PluginStartup function is called to allow plugin specific initialization. We
// increment the argumented WaitGroup so the main process can wait for
// our shutdown function to return during shutdown.
func PluginStartup() {
	logger.Info("PluginStartup(%s) has been called\n")
	dispatch.InsertNfqueueSubscription("dns", 2, PluginNfqueueHandler)
}

// PluginShutdown function called when the daemon is shutting down. We call Done
// for the argumented WaitGroup to let the main process know we're finished.
func PluginShutdown() {
	logger.Info("PluginShutdown(%s) has been called\n")
}

// PluginNfqueueHandler is called to handle nfqueue packet data. We only
// look at DNS packets, extracting the QNAME and putting it in the session table.
func PluginNfqueueHandler(mess dispatch.NfqueueMessage, ctid uint32, newSession bool) dispatch.NfqueueResult {
	var result dispatch.NfqueueResult
	result.Owner = "dns"
	result.SessionRelease = true
	result.PacketMark = 0

	// get the DNS layer
	dnsLayer := mess.Packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return result
	}

	dns := dnsLayer.(*layers.DNS)

	if dns.QDCount < 1 {
		return result
	}

	query := dns.Questions[0]
	logger.Info("DNS QUERY DETECTED NAME:%s TYPE:%d CLASS:%d\n", query.Name, query.Type, query.Class)

	// use the channel to return our result
	return result
}
