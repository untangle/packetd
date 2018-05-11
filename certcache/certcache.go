package certcache

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/untangle/packetd/support"
	"sync"
)

var localMutex sync.Mutex

//-----------------------------------------------------------------------------

func Plugin_Startup(childsync *sync.WaitGroup) {
	support.LogMessage("Plugin_Startup(%s) has been called\n", "certcache")
	childsync.Add(1)
}

//-----------------------------------------------------------------------------

func Plugin_Goodbye(childsync *sync.WaitGroup) {
	support.LogMessage("Plugin_Goodbye(%s) has been called\n", "certcache")
	childsync.Done()
}

//-----------------------------------------------------------------------------

func Plugin_netfilter_handler(ch chan<- int32, tuple support.Tuple, ctid uint) {

	if tuple.ServerPort != 443 {
		ch <- 8
		return
	}

	client := fmt.Sprintf("%s", tuple.ClientAddr)

	// TODO - remove this hack once we can ignore locally generated traffic
	if client == "192.168.222.20" {
		ch <- 8
		return
	}

	var cert x509.Certificate
	var ok bool

	localMutex.Lock()

	if cert, ok = support.FindCertificate(client); ok {
		support.LogMessage("Loading certificate for %s\n", tuple.ServerAddr)
	} else {
		support.LogMessage("Fetching certificate for %s\n", tuple.ServerAddr)

		conf := &tls.Config{
			InsecureSkipVerify: true,
		}

		target := fmt.Sprintf("%s:443", tuple.ServerAddr)
		conn, err := tls.Dial("tcp", target, conf)
		if err != nil {
			support.LogMessage("TLS ERROR: %s\n", err)
		}

		cert = *conn.ConnectionState().PeerCertificates[0]
		support.InsertCertificate(client, cert)
		conn.Close()
	}

	localMutex.Unlock()
	support.LogMessage("CERTIFICATE: %s\n", cert.Subject)
	ch <- 8
}

//-----------------------------------------------------------------------------
