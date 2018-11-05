package dns

import (
	"github.com/google/gopacket/layers"
	"github.com/untangle/packetd/services/dict"
	"github.com/untangle/packetd/services/dispatch"
	"github.com/untangle/packetd/services/logger"
	"net"
	"sync"
	"time"
)

const pluginName = "dns"

// AddressHolder is used to cache DNS names and IP addresses
type AddressHolder struct {
	CreationTime time.Time
	ExpireTime   time.Time
	Address      net.IP
	Name         string
}

var shutdownChannel = make(chan bool)
var addressTable map[string]*AddressHolder
var addressMutex sync.Mutex

// PluginStartup function is called to allow plugin specific initialization. We
// increment the argumented WaitGroup so the main process can wait for
// our shutdown function to return during shutdown.
func PluginStartup() {
	logger.Info("PluginStartup(%s) has been called\n", pluginName)
	addressTable = make(map[string]*AddressHolder)
	go cleanupTask()
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
	result.Owner = pluginName
	result.SessionRelease = true
	result.PacketMark = 0

	// for new sessions we look for the client and server IP in our DNS cache
	if newSession {
		var name string
		name = FindAddress(mess.MsgTuple.ClientAddress)
		if len(name) > 0 {
			logger.Debug("Setting client_dns_hint %s for %d\n", name, mess.Session.SessionID)
			dict.AddSessionEntry(mess.Session.ConntrackID, "client_dns_hint", name)
		}
		name = FindAddress(mess.MsgTuple.ServerAddress)
		if len(name) > 0 {
			logger.Debug("Setting server_dns_hint %s for %d\n", name, mess.Session.SessionID)
			dict.AddSessionEntry(mess.Session.ConntrackID, "server_dns_hint", name)
		}
	}

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

		// save the qname in the session attachments and turn off release flag so we get the response
		dispatch.PutSessionAttachment(mess.Session, "dns_query", string(query.Name))
		result.SessionRelease = false
	} else {
		qname := dispatch.GetSessionAttachment(mess.Session, "dns_query")

		// make sure we have the query name
		if qname == nil {
			return result
		}

		// make sure there is at least one answer record
		if dns.ANCount < 1 {
			return result
		}

		for _, val := range dns.Answers {
			if (val.Type != layers.DNSTypeA) && (val.Type != layers.DNSTypeAAAA) {
				continue
			}
			logger.Debug("DNS REPLY DETECTED NAME:%s TTL:%d IP:%v\n", qname, val.TTL, val.IP)
			insertAddress(val.IP, qname.(string), val.TTL)
		}
	}

	// use the channel to return our result
	return result
}

// FindAddress fetches the cached name for the argumented address.
func FindAddress(finder net.IP) string {
	addressMutex.Lock()
	entry := addressTable[finder.String()]
	addressMutex.Unlock()
	if entry != nil {
		return entry.Name
	}
	return ""
}

// insertAddress adds an address and name to the cache
func insertAddress(finder net.IP, name string, ttl uint32) {
	holder := new(AddressHolder)
	holder.CreationTime = time.Now()
	holder.ExpireTime = time.Now()
	holder.ExpireTime.Add(time.Second * time.Duration(ttl))
	holder.Address = make(net.IP, len(finder))
	copy(holder.Address, finder)
	holder.Name = name
	addressMutex.Lock()
	if addressTable[finder.String()] != nil {
		delete(addressTable, finder.String())
	}
	addressTable[finder.String()] = holder
	addressMutex.Unlock()
}

// removeAddress removes an address from the cache
func removeAddress(finder net.IP) {
	addressMutex.Lock()
	delete(addressTable, finder.String())
	addressMutex.Unlock()
}

// cleanAddressTable cleans the address table by removing stale entries
func cleanAddressTable() {
	var counter int
	nowtime := time.Now()

	for key, val := range addressTable {
		if val.ExpireTime.Unix() < nowtime.Unix() {
			logger.Debug("DNS Leaving ADDR:%s in table\n", key)
			continue
		}
		logger.Debug("DNS Removing ADDR:%s NAME:%s from table\n", val.Address.String(), val.Name)
		removeAddress(val.Address)
		counter++
	}

	logger.Debug("DNS REMOVED:%d REMAINING:%d\n", counter, len(addressTable))
}

// periodic task to clean the address table
func cleanupTask() {
	for {
		select {
		case <-shutdownChannel:
			shutdownChannel <- true
			return
		case <-time.After(60 * time.Second):
			cleanAddressTable()
		}
	}
}
