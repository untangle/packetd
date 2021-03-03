package threatprevention

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"encoding/hex"
	"strconv"

	"github.com/untangle/packetd/services/dispatch"
	"github.com/untangle/packetd/services/logger"
	"github.com/untangle/packetd/services/kernel"
	"github.com/untangle/packetd/services/settings"
	"github.com/untangle/packetd/services/webroot"
)

const pluginName = "threatprevention"
var tpLevel int
var tpEnabled bool = false

var privateIPBlocks []*net.IPNet
var rejectInfo map[string]interface{}

type contextKey struct {
	key string
  }
var ConnContextKey = &contextKey{"http-conn"}

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

	// Read in threat prevetion settings, and register callback for changes
	syncCallbackHandler()
	settings.RegisterSyncCallback(syncCallbackHandler)

	// Need basic http server to respond to redirect to inform user why they were blocked.
	server := http.Server{
	  Addr: ":8485",
	  ConnContext: SaveConnInContext,
	  Handler: http.HandlerFunc(tpRedirectHandler),
	}
	go server.ListenAndServe()

	// Need basic https server to respond to redirect to inform user why they were blocked.
	sslserver := http.Server{
		Addr: ":8486",
		ConnContext: SaveConnInContext,
		Handler: http.HandlerFunc(tpRedirectHandler),
	  }
	go sslserver.ListenAndServeTLS("/tmp/cert.pem", "/tmp/cert.key")


	rejectInfo = make(map[string]interface{})
	

	dispatch.InsertNfqueueSubscription(pluginName, dispatch.ThreatPreventionPriority, TpNfqueueHandler)
}

// PluginShutdown function called when the daemon is shutting down. We call Done
// for the argumented WaitGroup to let the main process know we're finished.
func PluginShutdown() {
	logger.Info("PluginShutdown(%s) has been called\n", pluginName)
}

// Is called when we do a sync setting. Need to update threat level.
func syncCallbackHandler() {
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
		logger.Info("Failed to get threatprevention level. Default to level 80\n")
		tpLevel = 80
	}
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
	webrootResult, err := webroot.IPLookup(dstAddr.String())
	score := webrootResult[0].Reputation
	logger.Trace("lookup %s, score %v\n", dstAddr.String(), score)
	if err != nil {
		logger.Warn("Not able to lookup %s\n", dstAddr.String())
	}
	if score == 0 { // Not scoring..
		result.SessionRelease = true
		return result
	}

	// Check if something should be blocked.
	logger.Info("pmark %b\n", mess.PacketMark)
	if score < tpLevel {
		logger.Info("blocked %s:%v, score %v\n", dstAddr.String(), mess.MsgTuple.ServerPort, score)
		result.SessionRelease = true // Is this right...
		// result.Pmark = mess.PacketMark | 0x02
		// Insert info on why it was rejected if http or https
		
		if mess.TCPLayer == nil || mess.MsgTuple.ServerPort != 443 {
			srcTpl := net.JoinHostPort(mess.MsgTuple.ServerAddress.String(), string(mess.MsgTuple.ClientPort))
			rejectInfo[srcTpl] = webrootResult
			// Need to redirect packet to localhost:8485
			kernel.NftSet("inet", "packetd", "tp_redirect", ctid, 0)
		} else {
			// Not HTTP or HTTPS, lets drop packet.
		}
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

func SaveConnInContext(ctx context.Context, c net.Conn) (context.Context) {
return context.WithValue(ctx, ConnContextKey, c)
}
func GetConn(r *http.Request) (net.Conn) {
return r.Context().Value(ConnContextKey).(net.Conn)
}

func tpRedirectHandler(w http.ResponseWriter, r *http.Request) {
	conn := GetConn(r)
	ip := conn.RemoteAddr()
	logger.Info("Look up reason for %v, %v\n", ip, rejectInfo[ip.String()])
	fmt.Fprintf(w, "<HTML><PRE> Your connection to %v was blocked by threat prevetion.</PRE></HTML>", rejectInfo[ip.String()])
}