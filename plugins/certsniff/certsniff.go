package certsniff

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"sync"
	"time"

	"github.com/untangle/packetd/services/certcache"
	"github.com/untangle/packetd/services/dispatch"
	"github.com/untangle/packetd/services/logger"
)

const pluginName = "certsniff"
const maxClientCount = 5  // number of packets to sniff for ClientHello before giving up
const maxServerCount = 20 // number of packets to sniff for the server certificate before giving up
const maxPacketCount = 10 // maximum number of packets we'll store and re-assemble while looking for the server certificate

type dataCollector struct {
	databuff [maxPacketCount][]byte
	sequence [maxPacketCount]uint32
	locker   sync.RWMutex
	total    int
}

// addPacket adds a packet of server data to the a dataCollector
func (ME *dataCollector) addPacket(buffer []byte, netseq uint32) {
	var total int

	// hold the read lock long enough to get the current buffer counter
	ME.locker.RLock()
	total = ME.total
	ME.locker.RUnlock()

	// make sure we don't overflow the packet collector
	if total == maxPacketCount {
		logger.Warn("Unable to add more data to collector\n")
		return
	}

	// hold the full lock long enough to get and increment the current buffer counter
	ME.locker.Lock()
	spot := ME.total
	ME.total++
	ME.locker.Unlock()

	// copy the argumented buffer and netseq value
	ME.databuff[spot] = make([]byte, len(buffer))
	copy(ME.databuff[spot], buffer)
	ME.sequence[spot] = netseq
}

// getBuffer assembles all the data packets into a single buffer in the correct order
func (ME *dataCollector) getBuffer() []byte {
	var holdData []byte
	var holdSpot uint32
	var fullbuff bytes.Buffer
	var total int

	// hold the lock long enough to gt the current buffer counter
	ME.locker.RLock()
	total = ME.total
	ME.locker.RUnlock()

	// sort the buffers using the TCP sequence number
	for j := 0; j < total-1; j++ {
		for k := (j + 1); k < total; k++ {
			if ME.sequence[j] > ME.sequence[k] {
				holdData = ME.databuff[j]
				holdSpot = ME.sequence[j]
				ME.databuff[j] = ME.databuff[k]
				ME.sequence[j] = ME.sequence[k]
				ME.databuff[k] = holdData
				ME.sequence[k] = holdSpot
			}
		}
	}

	// combine the data packets in a single buffer
	for i := 0; i < total; i++ {
		fullbuff.Write(ME.databuff[i])
	}

	// return the buffer as an array of bytes
	return fullbuff.Bytes()
}

// PluginStartup function is called to allow plugin specific initialization.
func PluginStartup() {
	logger.Info("PluginStartup(%s) has been called\n", pluginName)
	dispatch.InsertNfqueueSubscription(pluginName, dispatch.CertsniffPriority, PluginNfqueueHandler)
}

// PluginShutdown function called when the daemon is shutting down.
func PluginShutdown() {
	logger.Info("PluginShutdown(%s) has been called\n", pluginName)
}

// PluginNfqueueHandler is called to handle nfqueue packet data. We only
// look at TCP traffic without port 443 as destination, and we scan the
// first few packets looking for a TLS ClientHello message. If we find it,
// we continue looking at the traffic to see if we can locate and extract
// the certificate that is returned from the server. When found, we put the
// certificate in the cache, we attach it to the session, and we extract
// the interesting subject fields, and put them in the session table.

// PluginNfqueueHandler is called to handle nfqueue packet data.
func PluginNfqueueHandler(mess dispatch.NfqueueMessage, ctid uint32, newSession bool) dispatch.NfqueueResult {
	var result dispatch.NfqueueResult
	var certHolder *certcache.CertificateHolder
	var dataBucket *dataCollector
	var found bool

	result.SessionRelease = false

	// we only look for certs in TCP traffic not going to server port 443
	// since those session will be handled by the certfetch plugin
	if mess.TCPLayer == nil || mess.Session.GetClientSideTuple().ServerPort == 443 {
		result.SessionRelease = true
		return result
	}

	// if the session already has a certificate attached we are done
	check := mess.Session.GetAttachment("certificate")
	if check != nil {
		result.SessionRelease = true
		return result
	}

	// look in the cache to see if we already have a certificate for this server:port
	clientSideTuple := mess.Session.GetClientSideTuple()
	findkey := fmt.Sprintf("%s:%d", clientSideTuple.ServerAddress, clientSideTuple.ServerPort)
	certHolder, found = certcache.FindCertificate(findkey)
	if found {
		certHolder.CertLocker.Lock()
		if certHolder.Available {
			logger.Debug("Loading cached certificate for %s ctid:%d\n", findkey, ctid)
			certcache.AttachCertificateToSession(mess.Session, certHolder.Certificate)
		}
		certHolder.CertLocker.Unlock()
		result.SessionRelease = true
		return result
	}

	// the session doesn't have a cert and we didn't find in cache
	// so get the tls_collector from the session attachments
	dataBucket, found = mess.Session.GetAttachment("tls_collector").(*dataCollector)

	// if we don't have a collector yet we are still looking for ClientHello
	if found == false {
		status := findClientHello(mess.Payload)

		// if we find the ClientHello create and attach a collector and return
		if status == true {
			logger.Debug("Found ClientHello for ctid:%d\n", ctid)
			dataBucket = new(dataCollector)
			mess.Session.PutAttachment("tls_collector", dataBucket)
			return result
		}

		// if we don't find ClientHello after a while just give up
		if mess.Session.GetPacketCount() > maxClientCount {
			result.SessionRelease = true
		}

		return result
	}

	// we found the collector so now we only care about data from the server
	if mess.ClientToServer {
		return result
	}

	// ignore packets without any payload
	if len(mess.Payload) == 0 {
		return result
	}

	// add the packet to our data collector
	dataBucket.addPacket(mess.Payload, mess.TCPLayer.Seq)

	// look for the server certificate in the collector
	status := findCertificates(dataBucket.getBuffer(), mess)

	// if we find the certificate remove the collector attachment and release
	if status == true {
		mess.Session.DeleteAttachment("tls_collector")
		result.SessionRelease = true
	}

	// if we don't find the server certificate after a while just give up
	if mess.Session.GetPacketCount() > maxServerCount {
		result.SessionRelease = true
	}

	return result
}

/*

This table describes the structure of a TLS handshake message

Size   Description					Offset
--------------------------------------------------------------
1      Record Content Type			0
1      SSL MAJ Version				1
1      SSL MIN Version              2
2      Record Length				3
1      Handshake Type				5
3      Message Length				6
2      Client Preferred Version		9
4      Client Epoch GMT				11
28     28 Random Bytes				15
1      Session ID Length			43
0+     Session ID Data
2      Cipher Suites Length
0+     Cipher Suites Data
1      Compression Methods Length
0+     Compression Methods Data
2      Extensions Length
0+     Extensions Data

These are the handshake message types

Type                      dec    hex
---------------------------------------
HELLO_REQUEST              0     0x00
CLIENT_HELLO               1     0x01
SERVER_HELLO               2     0x02
CERTIFICATE               11     0x0B
SERVER_KEY_EXCHANGE       12     0x0C
CERTIFICATE_REQUEST       13     0x0D
SERVER_DONE               14     0x0E
CERTIFICATE_VERIFY        15     0x0F
CLIENT_KEY_EXCHANGE       16     0x10
FINISHED                  20     0x14

This table describes the structure of the CERTIFICATE message

Size   Description					Offset
--------------------------------------------------------------
1      Message Type                 0
3      Message Length               1
3      Certificate Chain Length     4
3      Certificate Length           7
0+     Certificate Data             10
...    Certificate Length
...    Certificate Data

*/

func findClientHello(buffer []byte) bool {
	var bufflen int
	bufflen = len(buffer)

	// if the packet is too short to hold a ClientHello just return
	if bufflen < 48 {
		return false
	}

	// check for the TLS handshake protocol
	if buffer[0] != 0x16 {
		return false
	}

	// check for SSLv3
	if buffer[1] != 0x03 {
		return false
	}

	// check for ClientHello message type
	if buffer[5] != 0x01 {
		return false
	}

	return true
}

func findCertificates(buffer []byte, mess dispatch.NfqueueMessage) bool {
	var bufflen int
	var reclen int
	var msglen int
	var recoff int
	var msgoff int
	var loopcheck int

	// start at the beginning of the buffer
	bufflen = len(buffer)
	recoff = 0

	// if the packet is too short to hold a ServerHello just return
	if bufflen < 53 {
		return false
	}

	// walk through each TLS record
	for {
		loopcheck++
		if loopcheck > 100 {
			logger.Err("Constraint failed: %v %v\n", loopcheck, recoff)
			return false
		}

		// make sure we have enough data to extract the record length
		if (recoff + 4) >= bufflen {
			return false
		}

		// extract the record length
		reclen = int(buffer[recoff+3])<<8 + int(buffer[recoff+4])

		// if we don't have the complete record return and wait for more data
		if (recoff + reclen) >= bufflen {
			return false
		}

		// if this isn't a valid TLS handshake record we give up
		if buffer[recoff] != 0x16 {
			return true
		}

		// if this isn't an SSLv3 record we give up
		if buffer[recoff+1] != 0x03 {
			return true
		}

		msgoff = (recoff + 5)

		// walk through each handshake message in the TLS record
		var loopcheck2 int
		for {
			loopcheck2++
			if loopcheck2 > 100 {
				logger.Err("Constraint failed: %v %v\n", loopcheck2, msgoff)
				return false
			}

			// when we reach the end of the record break out of the message walk
			if msgoff >= (recoff + reclen + 5) {
				break
			}

			// extract the message length
			msglen = int(buffer[msgoff+1])<<16 + int(buffer[msgoff+2])<<8 + int(buffer[msgoff+3])

			// if the handshake message is larger than the buffer we have a problem
			if (msgoff + msglen + 4) >= bufflen {
				break
			}

			// look for the CERTIFICATE handshake message and extract the certificate
			if buffer[msgoff] == 0x0B {
				// get the length of the first certificate
				clen := int(buffer[msgoff+7])<<16 + int(buffer[msgoff+8])<<8 + int(buffer[msgoff+9])

				// parse the raw certificate data
				cert, err := x509.ParseCertificate(buffer[msgoff+10 : msgoff+10+clen])
				if err != nil {
					logger.Err("Error %v extracting certificate\n", err)
				} else {
					clientSideTuple := mess.Session.GetClientSideTuple()
					findkey := fmt.Sprintf("%s:%d", clientSideTuple.ServerAddress, clientSideTuple.ServerPort)
					logger.Debug("Creating cached certificate for %s [%v]\n", findkey, cert.Subject)
					holder := new(certcache.CertificateHolder)
					holder.CreationTime = time.Now()
					holder.Certificate = *cert
					holder.Available = true
					certcache.AttachCertificateToSession(mess.Session, *cert)
					certcache.InsertCertificate(findkey, holder)
				}
				return true
			}

			msgoff += (msglen + 4)
		}
		// skip over the record header and length
		recoff += (reclen + 5)
	}
}
