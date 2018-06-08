package certcache

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/untangle/packetd/conndict"
	"github.com/untangle/packetd/support"
	"strings"
	"sync"
)

var appname = "certcache"
var localMutex sync.Mutex

//-----------------------------------------------------------------------------

// PluginStartup function is called to allow plugin specific initialization. We
// increment the argumented WaitGroup so the main process can wait for
// our goodbye function to return during shutdown.
func PluginStartup(childsync *sync.WaitGroup) {
	support.LogMessage(support.LogInfo, appname, "PluginStartup(%s) has been called\n", appname)
	support.InsertNetfilterSubscription(appname, 1, PluginNetfilterHandler)
	childsync.Add(1)
}

//-----------------------------------------------------------------------------

// PluginGoodbye function called when the daemon is shutting down. We call Done
// for the argumented WaitGroup to let the main process know we're finished.
func PluginGoodbye(childsync *sync.WaitGroup) {
	support.LogMessage(support.LogInfo, appname, "PluginGoodbye(%s) has been called\n", appname)
	childsync.Done()
}

//-----------------------------------------------------------------------------

// PluginNetfilterHandler is called to handle netfilter packet data. We only
// look at traffic with port 443 as destination. When detected, we load
// the server certificate from our cache or fetch it from the server and
// store it in our cache. Once we have the cert, we attach it to the session,
// extract the interesting subject fields, and put them in the conndict.
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

	ch <- result
}

//-----------------------------------------------------------------------------

func setConnDictPair(field string, value string, ctid uint) {
	output := strings.Replace(value, ",", "-", -1)
	err := conndict.SetPair(field, output, ctid)
	if err != nil {
		support.LogMessage(support.LogWarning, appname, "SetPair(%s,%s,%d) ERROR: %v\n", field, output, ctid, err)
	} else {
		support.LogMessage(support.LogDebug, appname, "SetPair(%s,%s,%d) SUCCESS\n", field, output, ctid)
	}
}

//-----------------------------------------------------------------------------

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

	err := conndict.SetPair(field, output, ctid)
	if err != nil {
		support.LogMessage(support.LogWarning, appname, "SetPair(%s,%s,%d) ERROR: %v\n", field, output, ctid, err)
	} else {
		support.LogMessage(support.LogDebug, appname, "SetPair(%s,%s,%d) SUCCESS\n", field, output, ctid)
	}
}

//-----------------------------------------------------------------------------

// This was pulled from https://github.com/polvi/sni/sni.go

func extractSNIhostname(b []byte) string {
	rest := b[5:]
	current := 0
	handshakeType := rest[0]
	current++

	if handshakeType != 0x1 {
		support.LogMessage(support.LogDebug, appname, "Packet does not contain TLS ClientHello message\n")
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
		support.LogMessage(support.LogDebug, appname, "Packet does not contain TLS extensions\n")
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
				support.LogMessage(support.LogDebug, appname, "Extension is not a hostname\n")
				return ""
			}
			nameLen := (int(rest[current]) << 8) + int(rest[current+1])
			current += 2
			hostname = string(rest[current : current+nameLen])
		}

		current += extensionDataLength
	}

	if hostname == "" {
		support.LogMessage(support.LogDebug, appname, "No SNI hostname detected\n")
		return ""
	}

	return hostname
}

//-----------------------------------------------------------------------------
