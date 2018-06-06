package certcache

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/untangle/packetd/conndict"
	"github.com/untangle/packetd/support"
	"sync"
)

var appname = "certcache"
var localMutex sync.Mutex

//-----------------------------------------------------------------------------

// PluginStartup function is called to allow plugin specific initialization. We
// increment the argumented WaitGroup so the main process can wait for
// our goodbye function to return during shutdown.
func PluginStartup(childsync *sync.WaitGroup) {
	support.LogMessage(support.LogInfo, appname, "PluginStartup(%s) has been called\n", "certcache")
	support.InsertNetfilterSubscription(appname, 1, PluginNetfilterHandler)
	childsync.Add(1)
}

//-----------------------------------------------------------------------------

// PluginGoodbye function called when the daemon is shutting down. We call Done
// for the argumented WaitGroup to let the main process know we're finished.
func PluginGoodbye(childsync *sync.WaitGroup) {
	support.LogMessage(support.LogInfo, appname, "PluginGoodbye(%s) has been called\n", "certcache")
	childsync.Done()
}

//-----------------------------------------------------------------------------

// PluginNetfilterHandler is called to handle netfilter packet data. We extract
// the source and destination IP address from the packet, lookup the GeoIP
// country code for each, and store them in the conntrack dictionary.
func PluginNetfilterHandler(ch chan<- support.SubscriptionResult, mess support.TrafficMessage, ctid uint) {
	var result support.SubscriptionResult
	result.Owner = appname
	result.PacketMark = 0
	result.SessionRelease = true

	if mess.Tuple.ServerPort != 443 {
		ch <- result
		return
	}

	client := fmt.Sprintf("%s", mess.Tuple.ClientAddr)

	// TODO - remove this hack once we can ignore locally generated traffic
	if client == "192.168.222.20" {
		ch <- result
		return
	}

	var cert x509.Certificate
	var ok bool

	localMutex.Lock()

	if cert, ok = support.FindCertificate(client); ok {
		support.LogMessage(support.LogInfo, appname, "Loading certificate for %s\n", mess.Tuple.ServerAddr)
	} else {
		support.LogMessage(support.LogInfo, appname, "Fetching certificate for %s\n", mess.Tuple.ServerAddr)

		conf := &tls.Config{
			InsecureSkipVerify: true,
		}

		target := fmt.Sprintf("%s:443", mess.Tuple.ServerAddr)
		conn, err := tls.Dial("tcp", target, conf)
		defer conn.Close()

		if err != nil {
			support.LogMessage(support.LogWarning, appname, "TLS ERROR: %s\n", err)
			ch <- result
			return
		}

		if len(conn.ConnectionState().PeerCertificates) < 1 {
			support.LogMessage(support.LogWarning, appname, "Could not fetch certificate from %s\n", mess.Tuple.ServerAddr)
			ch <- result
			return
		}

		cert = *conn.ConnectionState().PeerCertificates[0]
		support.InsertCertificate(client, cert)
	}

	mess.Session.SessionCertificate = cert

	localMutex.Unlock()

	// TODO - need better parsing of the cert subject and issuer

	subject := fmt.Sprintf("%v", cert.Subject)
	issuer := fmt.Sprintf("%v", cert.Issuer)

	errs := conndict.SetPair("CertSubject", subject, ctid)
	if errs != nil {
		support.LogMessage(support.LogWarning, appname, "SetPair(CertSubject) ERROR: %s\n", errs)
	} else {
		support.LogMessage(support.LogDebug, appname, "SetPair(CertSubject) %d = %s\n", ctid, subject)
	}

	erri := conndict.SetPair("CertIssuer", issuer, ctid)
	if erri != nil {
		support.LogMessage(support.LogWarning, appname, "SetPair(CertIssuer) ERROR: %s\n", erri)
	} else {
		support.LogMessage(support.LogDebug, appname, "SetPair(CertIssuer) %d = %s\n", ctid, string(issuer))
	}

	ch <- result
}

//-----------------------------------------------------------------------------
