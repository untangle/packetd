package certcache

import "fmt"
import "sync"
import "crypto/tls"

import "github.com/untangle/packetd/support"

/*---------------------------------------------------------------------------*/
func Plugin_Startup(childsync *sync.WaitGroup) {
	support.LogMessage("Plugin_Startup(%s) has been called\n", "certcache")
	childsync.Add(1)
}

/*---------------------------------------------------------------------------*/
func Plugin_Goodbye(childsync *sync.WaitGroup) {
	support.LogMessage("Plugin_Goodbye(%s) has been called\n", "certcache")
	childsync.Done()
}

/*---------------------------------------------------------------------------*/
func Plugin_conntrack_handler(message int, entry *support.ConntrackEntry) {

	// TODO - move this to the netfilter handler and store the cert in the session object

	if (message != 'N') { return }
	if (entry.SessionTuple.ServerPort != 443) { return }

	client := fmt.Sprintf("%s", entry.SessionTuple.ClientAddr)
	if (client == "192.168.222.20") { return }
	support.LogMessage("Fetching certificate CLIENT:%s SERVER:%s\n", client, entry.SessionTuple.ServerAddr)

	conf := &tls.Config {
		InsecureSkipVerify: true,
    }

	target := fmt.Sprintf("%s:443", entry.SessionTuple.ServerAddr)
	conn, err := tls.Dial("tcp", target, conf)
    if err != nil {
		support.LogMessage("TLS ERROR: %s\n", err)
    }

	support.LogMessage("CERTIFICATE: %s\n",conn.ConnectionState().PeerCertificates[0].Subject)
	conn.Close()
}

/*---------------------------------------------------------------------------*/
