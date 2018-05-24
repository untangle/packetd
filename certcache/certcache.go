package certcache

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/untangle/packetd/support"
	"sync"
)

var logsrc = "certcache"
var localMutex sync.Mutex

//-----------------------------------------------------------------------------

// PluginStartup function is called to allow plugin specific initialization. We
// increment the argumented WaitGroup so the main process can wait for
// our goodbye function to return during shutdown.
func PluginStartup(childsync *sync.WaitGroup) {
	support.LogMessage(support.LogInfo, logsrc, "PluginStartup(%s) has been called\n", "certcache")
	childsync.Add(1)
}

//-----------------------------------------------------------------------------

// PluginGoodbye function called when the daemon is shutting down. We call Done
// for the argumented WaitGroup to let the main process know we're finished.
func PluginGoodbye(childsync *sync.WaitGroup) {
	support.LogMessage(support.LogInfo, logsrc, "PluginGoodbye(%s) has been called\n", "certcache")
	childsync.Done()
}

//-----------------------------------------------------------------------------

// PluginNetfilterHandler is called to handle netfilter packet data. We extract
// the source and destination IP address from the packet, lookup the GeoIP
// country code for each, and store them in the conntrack dictionary.
func PluginNetfilterHandler(ch chan<- uint32, mess support.TrafficMessage, ctid uint) {

	if mess.MsgTuple.ServerPort != 443 {
		ch <- 8
		return
	}

	client := fmt.Sprintf("%s", mess.MsgTuple.ClientAddr)

	// TODO - remove this hack once we can ignore locally generated traffic
	if client == "192.168.222.20" {
		ch <- 8
		return
	}

	var cert x509.Certificate
	var ok bool

	localMutex.Lock()

	if cert, ok = support.FindCertificate(client); ok {
		support.LogMessage(support.LogInfo, logsrc, "Loading certificate for %s\n", mess.MsgTuple.ServerAddr)
	} else {
		support.LogMessage(support.LogInfo, logsrc, "Fetching certificate for %s\n", mess.MsgTuple.ServerAddr)

		conf := &tls.Config{
			InsecureSkipVerify: true,
		}

		target := fmt.Sprintf("%s:443", mess.MsgTuple.ServerAddr)
		conn, err := tls.Dial("tcp", target, conf)
		if err != nil {
			support.LogMessage(support.LogWarning, logsrc, "TLS ERROR: %s\n", err)
		}

		cert = *conn.ConnectionState().PeerCertificates[0]
		support.InsertCertificate(client, cert)
		conn.Close()
	}

	// TODO - should the cert also be attached to the session?

	localMutex.Unlock()
	support.LogMessage(support.LogDebug, logsrc, "CERTIFICATE: %s\n", cert.Subject)
	ch <- 8
}

//-----------------------------------------------------------------------------
