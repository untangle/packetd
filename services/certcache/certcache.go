package certcache

import (
	"crypto/x509"
	"github.com/untangle/packetd/services/dict"
	"github.com/untangle/packetd/services/dispatch"
	"github.com/untangle/packetd/services/logger"
	"strings"
	"sync"
	"time"
)

const cleanTimeout = 86400

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

// Startup function is called to allow service specific initialization.
func Startup() {
	certificateTable = make(map[string]*CertificateHolder)
	go cleanupTask()
}

// Shutdown function called when the daemon is shutting down.
func Shutdown() {
	// Send shutdown signal to cleanupTask and wait for it to return
	shutdownChannel <- true
	select {
	case <-shutdownChannel:
	case <-time.After(10 * time.Second):
		logger.Err("Failed to properly shutdown certcache cleanupTask\n")
	}
}

// AttachCertificateToSession is called to attach a certificate to a session entry and
// to populate the dictionary  with details about the certificate
func AttachCertificateToSession(session *dispatch.SessionEntry, certificate x509.Certificate) {

	dispatch.PutSessionAttachment(session, "certificate", certificate)

	setSessionEntry("certificate_subject_cn", certificate.Subject.CommonName, session.ConntrackID)
	setSessionEntry("certificate_subject_sn", certificate.Subject.SerialNumber, session.ConntrackID)
	setSessionList("certificate_subject_c", certificate.Subject.Country, session.ConntrackID)
	setSessionList("certificate_subject_o", certificate.Subject.Organization, session.ConntrackID)
	setSessionList("certificate_subject_ou", certificate.Subject.OrganizationalUnit, session.ConntrackID)
	setSessionList("certificate_subject_l", certificate.Subject.Locality, session.ConntrackID)
	setSessionList("certificate_subject_p", certificate.Subject.Province, session.ConntrackID)
	setSessionList("certificate_subject_sa", certificate.Subject.StreetAddress, session.ConntrackID)
	setSessionList("certificate_subject_pc", certificate.Subject.PostalCode, session.ConntrackID)
	setSessionList("certificate_subject_san", certificate.DNSNames, session.ConntrackID)

	setSessionEntry("certificate_issuer_cn", certificate.Issuer.CommonName, session.ConntrackID)
	setSessionEntry("certificate_issuer_sn", certificate.Issuer.SerialNumber, session.ConntrackID)
	setSessionList("certificate_issuer_c", certificate.Issuer.Country, session.ConntrackID)
	setSessionList("certificate_issuer_o", certificate.Issuer.Organization, session.ConntrackID)
	setSessionList("certificate_issuer_ou", certificate.Issuer.OrganizationalUnit, session.ConntrackID)
	setSessionList("certificate_issuer_l", certificate.Issuer.Locality, session.ConntrackID)
	setSessionList("certificate_issuer_p", certificate.Issuer.Province, session.ConntrackID)
	setSessionList("certificate_issuer_sa", certificate.Issuer.StreetAddress, session.ConntrackID)
	setSessionList("certificate_issuer_pc", certificate.Issuer.PostalCode, session.ConntrackID)
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

// FindCertificate fetches the cached certificate for the argumented address.
func FindCertificate(finder string) (*CertificateHolder, bool) {
	certificateMutex.Lock()
	entry, status := certificateTable[finder]
	certificateMutex.Unlock()
	return entry, status
}

// InsertCertificate adds a certificate to the cache
func InsertCertificate(finder string, holder *CertificateHolder) {
	certificateMutex.Lock()
	certificateTable[finder] = holder
	certificateMutex.Unlock()
}

// RemoveCertificate removes a certificate from the cache
func RemoveCertificate(finder string) {
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
		RemoveCertificate(key)
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
