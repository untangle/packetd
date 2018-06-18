package certcache

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/untangle/packetd/services/conndict"
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
var appname = "certcache"
var localMutex sync.Mutex

// PluginStartup function is called to allow plugin specific initialization. We
// increment the argumented WaitGroup so the main process can wait for
// our shutdown function to return during shutdown.
func PluginStartup() {
	logger.LogMessage(logger.LogInfo, appname, "PluginStartup(%s) has been called\n", appname)
	certificateTable = make(map[string]CertificateHolder)
	go cleanupTask()

	dispatch.InsertNfqueueSubscription(appname, 2, PluginNfqueueHandler)
}

// PluginShutdown function called when the daemon is shutting down. We call Done
// for the argumented WaitGroup to let the main process know we're finished.
func PluginShutdown() {
	// Send shutdown signal to cleanupTask and wait for it to return
	shutdownChannel <- true
	select {
	case <-shutdownChannel:
	case <-time.After(10 * time.Second):
		logger.LogMessage(logger.LogErr, appname, "Failed to properly shutdown cleanupTask\n")
	}

	logger.LogMessage(logger.LogInfo, appname, "PluginShutdown(%s) has been called\n", appname)
}

// PluginNfqueueHandler is called to handle nfqueue packet data. We only
// look at traffic with port 443 as destination. When detected, we load
// the server certificate from our cache or fetch it from the server and
// store it in our cache. Once we have the cert, we attach it to the session,
// extract the interesting subject fields, and put them in the conndict.
func PluginNfqueueHandler(mess dispatch.TrafficMessage, ctid uint, newSession bool) dispatch.NfqueueResult {
	var result dispatch.NfqueueResult
	result.Owner = appname
	result.PacketMark = 0
	result.SessionRelease = true

	// we only need to fetch certs for TCP traffic going to port 443
	if mess.TCPlayer == nil || mess.Tuple.ServerPort != 443 {
		return result
	}

	client := fmt.Sprintf("%s", mess.Tuple.ClientAddr)

	var cert x509.Certificate
	var ok bool

	localMutex.Lock()

	if cert, ok = findCertificate(client); ok {
		logger.LogMessage(logger.LogInfo, appname, "Loading certificate for %s\n", mess.Tuple.ServerAddr)
	} else {
		logger.LogMessage(logger.LogInfo, appname, "Fetching certificate for %s\n", mess.Tuple.ServerAddr)

		conf := &tls.Config{
			InsecureSkipVerify: true,
		}

		target := fmt.Sprintf("%s:443", mess.Tuple.ServerAddr)
		conn, err := tls.Dial("tcp", target, conf)
		defer conn.Close()

		if err != nil {
			logger.LogMessage(logger.LogWarn, appname, "TLS ERROR: %s\n", err)
			return result
		}

		if len(conn.ConnectionState().PeerCertificates) < 1 {
			logger.LogMessage(logger.LogWarn, appname, "Could not fetch certificate from %s\n", mess.Tuple.ServerAddr)
			return result
		}

		cert = *conn.ConnectionState().PeerCertificates[0]
		insertCertificate(client, cert)
	}

	mess.Session.SessionCertificate = cert

	localMutex.Unlock()

	setConnDictPair("SubjectCN", cert.Subject.CommonName, ctid)
	setConnDictPair("SubjectSN", cert.Subject.SerialNumber, ctid)
	setConnDictList("SubjectC", cert.Subject.Country, ctid)
	setConnDictList("SubjectO", cert.Subject.Organization, ctid)
	setConnDictList("SubjectOU", cert.Subject.OrganizationalUnit, ctid)
	setConnDictList("SubjectL", cert.Subject.Locality, ctid)
	setConnDictList("SubjectP", cert.Subject.Province, ctid)
	setConnDictList("SubjectSA", cert.Subject.StreetAddress, ctid)
	setConnDictList("SubjectPC", cert.Subject.PostalCode, ctid)
	setConnDictList("SubjectSAN", cert.DNSNames, ctid)

	setConnDictPair("IssuerCN", cert.Issuer.CommonName, ctid)
	setConnDictPair("IssuerSN", cert.Issuer.SerialNumber, ctid)
	setConnDictList("IssuerC", cert.Issuer.Country, ctid)
	setConnDictList("IssuerO", cert.Issuer.Organization, ctid)
	setConnDictList("IssuerOU", cert.Issuer.OrganizationalUnit, ctid)
	setConnDictList("IssuerL", cert.Issuer.Locality, ctid)
	setConnDictList("IssuerP", cert.Issuer.Province, ctid)
	setConnDictList("IssuerSA", cert.Issuer.StreetAddress, ctid)
	setConnDictList("IssuerPC", cert.Issuer.PostalCode, ctid)

	// grab the SNI hostname from the client hello
	hostname := extractSNIhostname(mess.Payload)
	if hostname != "" {
		setConnDictPair("ClientSNI", hostname, ctid)
	}

	return result
}

func setConnDictPair(field string, value string, ctid uint) {
	output := strings.Replace(value, ",", "-", -1)
	conndict.SetPair(field, output, ctid)
}

func setConnDictList(field string, value []string, ctid uint) {

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

	conndict.SetPair(field, output, ctid)
}

// This was pulled from https://github.com/polvi/sni/sni.go
func extractSNIhostname(b []byte) string {
	rest := b[5:]
	current := 0
	handshakeType := rest[0]
	current++

	if handshakeType != 0x1 {
		logger.LogMessage(logger.LogDebug, appname, "Packet does not contain a TLS ClientHello message\n")
		return ""
	}

	// Skip over another length
	current += 3
	// Skip over protocolversion
	current += 2
	// Skip over client epoch
	current += 4
	// Skip over random data
	current += 28
	// Skip over session ID
	sessionIDLength := int(rest[current])
	current++
	current += sessionIDLength

	cipherSuiteLength := (int(rest[current]) << 8) + int(rest[current+1])
	current += 2
	current += cipherSuiteLength

	compressionMethodLength := int(rest[current])
	current++
	current += compressionMethodLength

	if current > len(rest) {
		logger.LogMessage(logger.LogDebug, appname, "Packet does not contain TLS extensions\n")
		return ""
	}

	current += 2

	hostname := ""
	for current < len(rest) && hostname == "" {
		extensionType := (int(rest[current]) << 8) + int(rest[current+1])
		current += 2

		extensionDataLength := (int(rest[current]) << 8) + int(rest[current+1])
		current += 2

		if extensionType == 0 {

			// Skip over number of names as we're assuming there's just one
			current += 2

			nameType := rest[current]
			current++
			if nameType != 0 {
				logger.LogMessage(logger.LogDebug, appname, "Extension is not a hostname\n")
				return ""
			}
			nameLen := (int(rest[current]) << 8) + int(rest[current+1])
			current += 2
			hostname = string(rest[current : current+nameLen])
		}

		current += extensionDataLength
	}

	if hostname == "" {
		logger.LogMessage(logger.LogDebug, appname, "No SNI hostname detected\n")
		return ""
	}

	return hostname
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
		logger.LogMessage(logger.LogDebug, appname, "CERTIFICATE Removing %s from table\n", key)
	}

	logger.LogMessage(logger.LogDebug, appname, "CERTIFICATE REMOVED:%d REMAINING:%d\n", counter, len(certificateTable))
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
