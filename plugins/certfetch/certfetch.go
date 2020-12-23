package certfetch

import (
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/untangle/golang-shared/services/logger"
	"github.com/untangle/packetd/services/certcache"
	"github.com/untangle/packetd/services/dispatch"
)

const pluginName = "certfetch"
const fetchTimeout = 10 * time.Second

var localMutex sync.RWMutex

// PluginStartup function is called to allow plugin specific initialization.
func PluginStartup() {
	logger.Info("PluginStartup(%s) has been called\n", pluginName)
	dispatch.InsertNfqueueSubscription(pluginName, dispatch.CertfetchPriority, PluginNfqueueHandler)
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
	result.SessionRelease = true

	// release immediately as we only care about the first packet
	dispatch.ReleaseSession(mess.Session, pluginName)
	if !newSession {
		return result
	}

	// we only need to fetch certs for TCP traffic going to port 443
	if mess.TCPLayer == nil || mess.MsgTuple.ServerPort != 443 {
		return result
	}

	findkey := fmt.Sprintf("%s:%d", mess.MsgTuple.ServerAddress, mess.MsgTuple.ServerPort)

	var holder *certcache.CertificateHolder
	var target string
	var found bool

	localMutex.RLock()
	holder, found = certcache.FindCertificate(findkey)
	localMutex.RUnlock()

	if found {
		logger.Debug("Loading certificate for %s ctid:%d\n", findkey, ctid)
	} else {
		logger.Debug("Fetching certificate for %s ctid:%d\n", findkey, ctid)
		localMutex.Lock()
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

		if mess.IP6Layer != nil {
			target = fmt.Sprintf("[%s]:443", mess.MsgTuple.ServerAddress.String())
		} else {
			target = fmt.Sprintf("%s:443", mess.MsgTuple.ServerAddress.String())
		}

		conn, err := tls.DialWithDialer(dialer, "tcp", target, conf)
		if err != nil {
			//TLS errors are quite common in the real world
			//anytime a non SSL based TCP connection goes over port 443 it causes this
			//Log this at just debug level
			logger.Debug("TLS error: %s\n", err)
		} else {
			defer conn.Close()
		}

		holder.CertLocker.Lock()

		if conn != nil && len(conn.ConnectionState().PeerCertificates) > 0 {
			logger.Debug("Successfully fetched certificate from %s ctid:%d\n", findkey, ctid)
			holder.Certificate = *conn.ConnectionState().PeerCertificates[0]
			holder.Available = true
		} else {
			logger.Debug("Could not fetch certificate from %s ctid:%d\n", findkey, ctid)
			holder.Available = false
		}
		holder.CreationTime = time.Now()
		holder.CertLocker.Unlock()
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
	logger.Debug("Certificate %v found: %v ctid:%d\n", findkey, holder.Available, ctid)

	holder.CertLocker.Lock()

	// if the cert is available for this server attach the cert to the session
	// and put the details in the dictionary
	if holder.Available {
		certcache.AttachCertificateToSession(mess.Session, holder.Certificate)
	}

	holder.CertLocker.Unlock()

	return result
}
