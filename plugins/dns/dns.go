package dns

import (
	"github.com/google/gopacket/layers"
	"github.com/untangle/packetd/services/dict"
	"github.com/untangle/packetd/services/dispatch"
	"github.com/untangle/packetd/services/logger"
)

const pluginName = "dns"

// PluginStartup function is called to allow plugin specific initialization. We
// increment the argumented WaitGroup so the main process can wait for
// our shutdown function to return during shutdown.
func PluginStartup() {
	logger.Info("PluginStartup(%s) has been called\n", pluginName)
	dispatch.InsertNfqueueSubscription(pluginName, 2, PluginNfqueueHandler)
}

// PluginShutdown function called when the daemon is shutting down. We call Done
// for the argumented WaitGroup to let the main process know we're finished.
func PluginShutdown() {
	logger.Info("PluginShutdown(%s) has been called\n", pluginName)
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
	logger.Trace("ID:%d QR:%v OC:%d QD:%d AN:%d NS:%d AR:%d\n", dns.ID, dns.QR, dns.OpCode, dns.QDCount, dns.ANCount, dns.NSCount, dns.ARCount)

	// The QR flag will be false for a query, true for a response
	if dns.QR == false {
		// make sure there is at least one question record
		if dns.QDCount < 1 {
			return result
		}

		// use the first question record
		query := dns.Questions[0]

		// ignore requests for other than A and AAAA records
		if (query.Type != layers.DNSTypeA) && (query.Type != layers.DNSTypeAAAA) {
			return result
		}

		logger.Debug("DNS QUERY DETECTED NAME:%s TYPE:%d CLASS:%d\n", query.Name, query.Type, query.Class)
		dict.AddSessionEntry(ctid, "dns_query", string(query.Name))
	} else {
		// make sure there is at least one answer record
		if dns.ANCount < 1 {
			return result
		}

		// use the first answer record
		reply := dns.Answers[0]

		// ignore answers that are not A or AAAA records
		if (reply.Type != layers.DNSTypeA) && (reply.Type != layers.DNSTypeAAAA) {
			return result
		}

		logger.Debug("DNS REPLY DETECTED VALUE:%v\n", reply.IP)
		dict.AddSessionEntry(ctid, "dns_reply", reply.IP)
	}

	// use the channel to return our result
	return result
}
