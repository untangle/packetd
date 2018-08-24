package certcache

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/untangle/packetd/services/dict"
	"github.com/untangle/packetd/services/dispatch"
	"github.com/untangle/packetd/services/logger"
	"net"
	"strings"
	"sync"
	"time"
)

const pluginName = "certcache"
const cleanTimeout = 86400
const fetchTimeout = 10 * time.Second

// CertificateHolder is used to cache SSL/TLS certificates
type CertificateHolder struct {
	CreationTime time.Time
	Certificate  x509.Certificate
	Available    bool
	WaitGroup    sync.WaitGroup
}

var shutdownChannel = make(chan bool)
var certificateTable map[string]*CertificateHolder
var certificateMutex sync.Mutex
var localMutex sync.Mutex

// PluginStartup function is called to allow plugin specific initialization.
func PluginStartup() {
	logger.Info("PluginStartup(%s) has been called\n", pluginName)
	certificateTable = make(map[string]*CertificateHolder)
	go cleanupTask()

	dispatch.InsertNfqueueSubscription(pluginName, 2, PluginNfqueueHandler)
}

// PluginShutdown function called when the daemon is shutting down.
func PluginShutdown() {
	// Send shutdown signal to cleanupTask and wait for it to return
	shutdownChannel <- true
	select {
	case <-shutdownChannel:
	case <-time.After(10 * time.Second):
		logger.Err("Failed to properly shutdown cleanupTask\n")
	}

	logger.Info("PluginShutdown(%s) has been called\n", pluginName)
}

// PluginNfqueueHandler is called to handle nfqueue packet data. We only
// look at traffic with port 443 as destination. When detected, we load
// the server certificate from our cache or fetch it from the server and
// store it in our cache. Once we have the cert, we attach it to the session,
// extract the interesting subject fields, and put them in the session table.
func PluginNfqueueHandler(mess dispatch.NfqueueMessage, ctid uint32, newSession bool) dispatch.NfqueueResult {
	var result dispatch.NfqueueResult
	result.Owner = pluginName
	result.PacketMark = 0
	result.SessionRelease = true

	// we only need to fetch certs for TCP traffic going to port 443
	if mess.TCPlayer == nil || mess.Tuple.ServerPort != 443 {
		return result
	}

	server := fmt.Sprintf("%s", mess.Tuple.ServerAddress)

	var holder *CertificateHolder
	var target string
	var found bool

	localMutex.Lock()

	holder, found = findCertificate(server)
	if found {
		localMutex.Unlock()
		logger.Debug("Loading certificate for %s\n", server)
	} else {
		logger.Debug("Fetching certificate for %s\n", server)
		holder = new(CertificateHolder)
		holder.WaitGroup.Add(1)
		insertCertificate(server, holder)
		localMutex.Unlock()

		conf := &tls.Config{
			InsecureSkipVerify: true,
		}
		dialer := &net.Dialer{
			Timeout: fetchTimeout,
		}

		if mess.IP6layer != nil {
			target = fmt.Sprintf("[%s]:443", server)
		} else {
			target = fmt.Sprintf("%s:443", server)
		}

		conn, err := tls.DialWithDialer(dialer, "tcp", target, conf)
		if err != nil {
			logger.Warn("TLS ERROR: %s\n", err)
		} else {
			defer conn.Close()
		}

		if conn != nil && len(conn.ConnectionState().PeerCertificates) > 0 {
			logger.Debug("Successfully fetched certificate from %s\n", server)
			holder.Certificate = *conn.ConnectionState().PeerCertificates[0]
			holder.Available = true
		} else {
			logger.Debug("Could not fetch certificate from %s\n", server)
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
	logger.Debug("Certificate %v found: %v\n", server, holder.Available)

	// if the cert is available for this server, add the metadata to the session dict
	if holder.Available {
		dispatch.PutSessionAttachment(mess.Session, "certificate", holder.Certificate)

		setSessionEntry("certificate_subject_cn", holder.Certificate.Subject.CommonName, ctid)
		setSessionEntry("certificate_subject_sn", holder.Certificate.Subject.SerialNumber, ctid)
		setSessionList("certificate_subject_c", holder.Certificate.Subject.Country, ctid)
		setSessionList("certificate_subject_o", holder.Certificate.Subject.Organization, ctid)
		setSessionList("certificate_subject_ou", holder.Certificate.Subject.OrganizationalUnit, ctid)
		setSessionList("certificate_subject_l", holder.Certificate.Subject.Locality, ctid)
		setSessionList("certificate_subject_p", holder.Certificate.Subject.Province, ctid)
		setSessionList("certificate_subject_sa", holder.Certificate.Subject.StreetAddress, ctid)
		setSessionList("certificate_subject_pc", holder.Certificate.Subject.PostalCode, ctid)
		setSessionList("certificate_subject_san", holder.Certificate.DNSNames, ctid)

		setSessionEntry("certificate_issuer_cn", holder.Certificate.Issuer.CommonName, ctid)
		setSessionEntry("certificate_issuer_sn", holder.Certificate.Issuer.SerialNumber, ctid)
		setSessionList("certificate_issuer_c", holder.Certificate.Issuer.Country, ctid)
		setSessionList("certificate_issuer_o", holder.Certificate.Issuer.Organization, ctid)
		setSessionList("certificate_issuer_ou", holder.Certificate.Issuer.OrganizationalUnit, ctid)
		setSessionList("certificate_issuer_l", holder.Certificate.Issuer.Locality, ctid)
		setSessionList("certificate_issuer_p", holder.Certificate.Issuer.Province, ctid)
		setSessionList("certificate_issuer_sa", holder.Certificate.Issuer.StreetAddress, ctid)
		setSessionList("certificate_issuer_pc", holder.Certificate.Issuer.PostalCode, ctid)
	}

	return result
}

func setSessionEntry(field string, value string, ctid uint32) {

	if len(value) == 0 {
		return
	}

	output := strings.Replace(value, ",", "-", -1)
	dict.AddSessionEntry(ctid, field, output)
}

func setSessionList(field string, value []string, ctid uint32) {

	if len(value) == 0 {
		return
	}

	var buffer string

	for index, item := range value {
		if index != 0 {
			buffer += "|"
		}
		buffer += item
	}

	if len(buffer) == 0 {
		return
	}

	output := strings.Replace(buffer, ",", "-", -1)
	dict.AddSessionEntry(ctid, field, output)
}

// findCertificate fetches the cached certificate for the argumented address.
func findCertificate(finder string) (*CertificateHolder, bool) {
	certificateMutex.Lock()
	entry, status := certificateTable[finder]
	certificateMutex.Unlock()
	return entry, status
}

// InsertCertificate adds a certificate to the cache
func insertCertificate(finder string, holder *CertificateHolder) {
	certificateMutex.Lock()
	certificateTable[finder] = holder
	certificateMutex.Unlock()
}

// removeCertificate removes a certificate from the cache
func removeCertificate(finder string) {
	certificateMutex.Lock()
	delete(certificateTable, finder)
	certificateMutex.Unlock()
}

// cleanCertificateTable cleans the certificate table by removing stale entries
func cleanCertificateTable() {
	var counter int
	nowtime := time.Now()

	for key, val := range certificateTable {
		if (nowtime.Unix() - val.CreationTime.Unix()) < cleanTimeout {
			continue
		}
		removeCertificate(key)
		counter++
		logger.Debug("Removing certificate for %s\n", key)
	}
}

// periodic task to clean the certificate table
func cleanupTask() {
	for {
		select {
		case <-shutdownChannel:
			shutdownChannel <- true
			return
		case <-time.After(60 * time.Second):
			cleanCertificateTable()
		}
	}
}
