package threatprevention

import (
	"net"
	"encoding/hex"
	"strconv"

	"github.com/untangle/packetd/services/dispatch"
	"github.com/untangle/packetd/services/logger"
	"github.com/untangle/packetd/services/settings"
	"github.com/untangle/packetd/services/webroot"
)

const pluginName = "threatprevention"
var tpLevel int
var tpEnabled bool = false

var privateIPBlocks []*net.IPNet

// PluginStartup function is called to allow plugin specific initialization. We
// increment the argumented WaitGroup so the main process can wait for
// our shutdown function to return during shutdown.
func PluginStartup() {
	logger.Info("PluginStartup(%s) has been called\n", pluginName)

	for _, cidr := range []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 unique local addr
	} {
		_, block, _ := net.ParseCIDR(cidr)
		privateIPBlocks = append(privateIPBlocks, block)
	}

	enabled, err := settings.GetSettings([]string{"threatprevention", "enabled"})
	if err != nil {
		logger.Warn("Failed to read setting value for setting threatprevention/enabled, error: %v\n", err.Error())
	}
	tpEnabled = enabled.(bool)
	// Need to load current threatprevention level from settings.
	sensitivity, err := settings.GetSettings([]string{"threatprevention", "sensitivity"})
	if err != nil {
		logger.Warn("Failed to read setting value for setting threatprevention/sensitivity, error: %v\n", err.Error())
	}
	tpLevel, err = strconv.Atoi(sensitivity.(string))
	if err != nil {
		tpLevel = 80
	}
	logger.Debug("tpLevel is %v\n", tpLevel)

	dispatch.InsertNfqueueSubscription(pluginName, dispatch.ThreatPreventionPriority, TpNfqueueHandler)
}

// PluginShutdown function called when the daemon is shutting down. We call Done
// for the argumented WaitGroup to let the main process know we're finished.
func PluginShutdown() {
	logger.Info("PluginShutdown(%s) has been called\n", pluginName)
}

// PluginNfqueueHandler receives a NfqueueMessage which includes a Tuple and
// a gopacket.Packet, along with the IP and TCP or UDP layer already extracted.
// We do whatever we like with the data, and when finished, we return an
// integer via the argumented channel with any bits set that we want added to
// the packet mark.
func TpNfqueueHandler(mess dispatch.NfqueueMessage, ctid uint32, newSession bool) dispatch.NfqueueResult {
	var result dispatch.NfqueueResult

	if mess.IP4Layer != nil {
		logger.Debug("NfqueueHandler received %d BYTES from %s to %s\n%s\n", mess.Length, mess.IP4Layer.SrcIP, mess.IP4Layer.DstIP, hex.Dump(mess.Packet.Data()))
	}
	if mess.IP6Layer != nil {
		logger.Debug("NfqueueHandler received %d BYTES from %s to %s\n%s\n", mess.Length, mess.IP6Layer.SrcIP, mess.IP6Layer.DstIP, hex.Dump(mess.Packet.Data()))
	}

	// We only care about HTTP or HTTPS request.
	// TODO: Anyway to filter this before we even get here..?
	if mess.TCPLayer == nil || mess.MsgTuple.ServerPort != 443 {
		result.SessionRelease = true
		return result
	}

	// var srcAddr net.IP
	var dstAddr net.IP

	if mess.IP6Layer != nil {
		// srcAddr = mess.IP6Layer.SrcIP
		dstAddr = mess.IP6Layer.DstIP
	}

	if mess.IP4Layer != nil {
		// srcAddr = mess.IP4Layer.SrcIP
		dstAddr = mess.IP4Layer.DstIP
	}

	// Release if the request is to private address space.
	if dstAddr != nil && isPrivateIP(dstAddr) {
		result.SessionRelease = true
		logger.Info("Address is private %s\n", dstAddr)
		return result
	} 
	
	// Lookup and get a score.
	
	score, err := webroot.IPLookup(dstAddr.String())

	logger.Trace("lookup %s, score %v\n", dstAddr.String(), score)
	if err != nil {
		logger.Warn("Not able to lookup %s\n", dstAddr.String())
	}
	if score == 0 { // Not scoring..
		result.SessionRelease = true
		return result
	}

	// Check if something should be blocked.
	if score < tpLevel {
		logger.Info("blocked %s:%v, score %v\n", dstAddr.String(), mess.MsgTuple.ServerPort, score)
		// Need to mark packet so it can be redirected and handled.
		
	}
	result.SessionRelease = true
	return result
}

func isPrivateIP(ip net.IP) bool {
	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}