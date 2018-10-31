package certfetch

import (
	"crypto/tls"
	"fmt"
	"github.com/untangle/packetd/services/certcache"
	"github.com/untangle/packetd/services/dispatch"
	"github.com/untangle/packetd/services/logger"
	"net"
	"sync"
	"time"
)

const pluginName = "certfetch"
const fetchTimeout = 10 * time.Second

var localMutex sync.Mutex

// PluginStartup function is called to allow plugin specific initialization.
func PluginStartup() {
	logger.Info("PluginStartup(%s) has been called\n", pluginName)
	dispatch.InsertNfqueueSubscription(pluginName, 2, PluginNfqueueHandler)
}

// PluginShutdown function called when the daemon is shutting down.
func PluginShutdown() {
	logger.Info("PluginShutdown(%s) has been called\n", pluginName)
}

// PluginNfqueueHandler is called to handle nfqueue packet data. We only
// look at TCP traffic with port 443 as destination. When detected, we load
// the server certificate from the cache or fetch it from the server and
// store it in the cache. Once we have the cert, we attach it to the session,
// extract the interesting subject fields, and put them in the session table.
func PluginNfqueueHandler(mess dispatch.NfqueueMessage, ctid uint32, newSession bool) dispatch.NfqueueResult {
	var result dispatch.NfqueueResult
	result.Owner = pluginName
	result.PacketMark = 0
	result.SessionRelease = true

	// release immediately as we only care about the first packet
	dispatch.ReleaseSession(mess.Session, pluginName)
	if !newSession {
		return result
	}

	// we only need to fetch certs for TCP traffic going to port 443
	if mess.TCPlayer == nil || mess.MsgTuple.ServerPort != 443 {
		return result
	}

	findkey := fmt.Sprintf("%s:%d", mess.MsgTuple.ServerAddress, mess.MsgTuple.ServerPort)

	var holder *certcache.CertificateHolder
	var target string
	var found bool

	localMutex.Lock()

	holder, found = certcache.FindCertificate(findkey)
	if found {
		localMutex.Unlock()
		logger.Debug("Loading certificate for %s\n", findkey)
	} else {
		logger.Debug("Fetching certificate for %s\n", findkey)

		holder = new(certcache.CertificateHolder)
		holder.WaitGroup.Add(1)
		certcache.InsertCertificate(findkey, holder)
		localMutex.Unlock()

		conf := &tls.Config{
			InsecureSkipVerify: true,
		}
		dialer := &net.Dialer{
			Timeout: fetchTimeout,
		}

		if mess.IP6layer != nil {
			target = fmt.Sprintf("[%s]:443", mess.MsgTuple.ServerAddress.String())
		} else {
			target = fmt.Sprintf("%s:443", mess.MsgTuple.ServerAddress.String())
		}

		conn, err := tls.DialWithDialer(dialer, "tcp", target, conf)
		if err != nil {
			logger.Warn("TLS ERROR: %s\n", err)
		} else {
			defer conn.Close()
		}

		if conn != nil && len(conn.ConnectionState().PeerCertificates) > 0 {
			logger.Debug("Successfully fetched certificate from %s\n", findkey)
			holder.Certificate = *conn.ConnectionState().PeerCertificates[0]
			holder.Available = true
		} else {
			logger.Debug("Could not fetch certificate from %s\n", findkey)
			holder.Available = false
		}
		holder.CreationTime = time.Now()
		holder.WaitGroup.Done()
	}

	// At this point the holder has either been retrieved or created
	if holder == nil {
		logger.Err("Constraint failed: nil cert holder\n")
		return result
	}

	// wait until the cert has been retrieved
	// this will only happen when two+ sessions requests the same cert at the same time
	// the first will fetch the cert, and the other threads will wait here
	holder.WaitGroup.Wait()
	logger.Debug("Certificate %v found: %v\n", findkey, holder.Available)

	// if the cert is available for this server attach the cert to the session
	// and put the details in the dictionary
	if holder.Available {
		certcache.AttachCertificateToSession(mess.Session, holder.Certificate)
	}

	return result
}
