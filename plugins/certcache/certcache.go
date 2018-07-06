package certcache

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/untangle/packetd/services/dict"
	"github.com/untangle/packetd/services/dispatch"
	"github.com/untangle/packetd/services/logger"
	"strings"
	"sync"
	"time"
)

// CertificateHolder is used to cache SSL/TLS certificates
type CertificateHolder struct {
	CreationTime time.Time
	Certificate  x509.Certificate
}

var shutdownChannel = make(chan bool)
var certificateTable map[string]CertificateHolder
var certificateMutex sync.Mutex
var localMutex sync.Mutex

// PluginStartup function is called to allow plugin specific initialization. We
// increment the argumented WaitGroup so the main process can wait for
// our shutdown function to return during shutdown.
func PluginStartup() {
	logger.LogInfo("PluginStartup(%s) has been called\n")
	certificateTable = make(map[string]CertificateHolder)
	go cleanupTask()

	dispatch.InsertNfqueueSubscription("certcache", 2, PluginNfqueueHandler)
}

// PluginShutdown function called when the daemon is shutting down. We call Done
// for the argumented WaitGroup to let the main process know we're finished.
func PluginShutdown() {
	// Send shutdown signal to cleanupTask and wait for it to return
	shutdownChannel <- true
	select {
	case <-shutdownChannel:
	case <-time.After(10 * time.Second):
		logger.LogErr("Failed to properly shutdown cleanupTask\n")
	}

	logger.LogInfo("PluginShutdown(%s) has been called\n")
}

// PluginNfqueueHandler is called to handle nfqueue packet data. We only
// look at traffic with port 443 as destination. When detected, we load
// the server certificate from our cache or fetch it from the server and
// store it in our cache. Once we have the cert, we attach it to the session,
// extract the interesting subject fields, and put them in the session table.
func PluginNfqueueHandler(mess dispatch.NfqueueMessage, ctid uint32, newSession bool) dispatch.NfqueueResult {
	var result dispatch.NfqueueResult
	result.Owner = "certcache"
	result.PacketMark = 0
	result.SessionRelease = true

	// we only need to fetch certs for TCP traffic going to port 443
	if mess.TCPlayer == nil || mess.Tuple.ServerPort != 443 {
		return result
	}

	client := fmt.Sprintf("%s", mess.Tuple.ClientAddress)

	var cert x509.Certificate
	var ok bool

	localMutex.Lock()

	if cert, ok = findCertificate(client); ok {
		logger.LogInfo("Loading certificate for %s\n", mess.Tuple.ServerAddress)
	} else {
		logger.LogInfo("Fetching certificate for %s\n", mess.Tuple.ServerAddress)

		conf := &tls.Config{
			InsecureSkipVerify: true,
		}

		target := fmt.Sprintf("%s:443", mess.Tuple.ServerAddress)
		conn, err := tls.Dial("tcp", target, conf)
		defer conn.Close()

		if err != nil {
			logger.LogWarn("TLS ERROR: %s\n", err)
			return result
		}

		if len(conn.ConnectionState().PeerCertificates) < 1 {
			logger.LogWarn("Could not fetch certificate from %s\n", mess.Tuple.ServerAddress)
			return result
		}

		cert = *conn.ConnectionState().PeerCertificates[0]
		insertCertificate(client, cert)
	}

	mess.Session.Attachments["certificate"] = cert

	localMutex.Unlock()

	setSessionEntry("certificate_subject_cn", cert.Subject.CommonName, ctid)
	setSessionEntry("certificate_subject_sn", cert.Subject.SerialNumber, ctid)
	setSessionList("certificate_subject_c", cert.Subject.Country, ctid)
	setSessionList("certificate_subject_o", cert.Subject.Organization, ctid)
	setSessionList("certificate_subject_ou", cert.Subject.OrganizationalUnit, ctid)
	setSessionList("certificate_subject_l", cert.Subject.Locality, ctid)
	setSessionList("certificate_subject_p", cert.Subject.Province, ctid)
	setSessionList("certificate_subject_sa", cert.Subject.StreetAddress, ctid)
	setSessionList("certificate_subject_pc", cert.Subject.PostalCode, ctid)
	setSessionList("certificate_subject_san", cert.DNSNames, ctid)

	setSessionEntry("certificate_issuer_cn", cert.Issuer.CommonName, ctid)
	setSessionEntry("certificate_issuer_sn", cert.Issuer.SerialNumber, ctid)
	setSessionList("certificate_issuer_c", cert.Issuer.Country, ctid)
	setSessionList("certificate_issuer_o", cert.Issuer.Organization, ctid)
	setSessionList("certificate_issuer_ou", cert.Issuer.OrganizationalUnit, ctid)
	setSessionList("certificate_issuer_l", cert.Issuer.Locality, ctid)
	setSessionList("certificate_issuer_p", cert.Issuer.Province, ctid)
	setSessionList("certificate_issuer_sa", cert.Issuer.StreetAddress, ctid)
	setSessionList("certificate_issuer_pc", cert.Issuer.PostalCode, ctid)

	return result
}

func setSessionEntry(field string, value string, ctid uint32) {
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

	output := strings.Replace(buffer, ",", "-", -1)

	dict.AddSessionEntry(ctid, field, output)
}

// findCertificate fetches the cached certificate for the argumented address.
func findCertificate(finder string) (x509.Certificate, bool) {
	certificateMutex.Lock()
	entry, status := certificateTable[finder]
	certificateMutex.Unlock()
	return entry.Certificate, status
}

// InsertCertificate adds a certificate to the cache
func insertCertificate(finder string, cert x509.Certificate) {
	var holder CertificateHolder
	holder.CreationTime = time.Now()
	holder.Certificate = cert
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
		if (nowtime.Unix() - val.CreationTime.Unix()) < 86400 {
			continue
		}
		removeCertificate(key)
		counter++
		logger.LogDebug("CERTIFICATE Removing %s from table\n", key)
	}

	logger.LogDebug("CERTIFICATE REMOVED:%d REMAINING:%d\n", counter, len(certificateTable))
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
