package tls

import (
	"bytes"
	"crypto/x509"
	"github.com/untangle/packetd/services/dispatch"
	"github.com/untangle/packetd/services/logger"
)

const pluginName = "tls"
const maxClientCount = 5
const maxServerCount = 20

// PluginStartup function is called to allow plugin specific initialization.
func PluginStartup() {
	logger.Info("PluginStartup(%s) has been called\n", pluginName)
	dispatch.InsertNfqueueSubscription(pluginName, 2, PluginNfqueueHandler)
}

// PluginShutdown function called when the daemon is shutting down.
func PluginShutdown() {
	logger.Info("PluginShutdown(%s) has been called\n", pluginName)
}

// PluginNfqueueHandler is called to handle nfqueue packet data.
func PluginNfqueueHandler(mess dispatch.NfqueueMessage, ctid uint32, newSession bool) dispatch.NfqueueResult {
	var result dispatch.NfqueueResult
	var collector *bytes.Buffer
	var ok bool

	result.Owner = pluginName
	result.PacketMark = 0
	result.SessionRelease = false

	// we only look for certs in TCP traffic not going to server port 443
	// since those will be handled by the certcache plugin
	if mess.TCPlayer == nil || mess.MsgTuple.ServerPort == 443 {
		result.SessionRelease = true
		return result
	}

	// get the tls_collector from the session attachments
	collector, ok = dispatch.GetSessionAttachment(mess.Session, "tls_collector").(*bytes.Buffer)

	// if we don't have a collector yet we are still looking for ClientHello
	if ok == false {
		status := findClientHello(mess.Payload)

		// if we find the ClientHello create and attach a collector and return
		if status == true {
			logger.Debug("Found ClientHello for %d\n", ctid)
			collector = new(bytes.Buffer)
			dispatch.PutSessionAttachment(mess.Session, "tls_collector", collector)
			return result
		}

		// if we don't find ClientHello after a while just give up
		if mess.Session.PacketCount > maxClientCount {
			result.SessionRelease = true
		}

		return result
	}

	// we found the collector so now we only care about data from the server
	if mess.CtoS {
		return result
	}

	// ignore packets without any payload
	if len(mess.Payload) == 0 {
		return result
	}

	// add the server data to the collector
	logger.Debug("Adding %d bytes to collector for %d\n", len(mess.Payload), ctid)
	collector.Write(mess.Payload)

	// look for the server certificate in the collector
	status := findCertificates(collector.Bytes(), mess.Session)

	// if we find the certificate remove the attachment and release
	if status == true {
		logger.Debug("Found server certificate for %d\n", ctid)
		dispatch.DelSessionAttachment(mess.Session, "tls_collector")
		result.SessionRelease = true
	}

	// if we don't find the server certificate after a while just give up
	if mess.Session.PacketCount > maxServerCount {
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

func findCertificates(buffer []byte, session *dispatch.SessionEntry) bool {
	var bufflen int
	var reclen int
	var msglen int
	var recoff int
	var msgoff int

	// start at the beginning of the buffer
	bufflen = len(buffer)
	recoff = 0

	// if the packet is too short to hold a ServerHello just return
	if bufflen < 53 {
		return false
	}

	// walk through each TLS record
	for {
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
		for {
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
					logger.Debug("Found server certificate: %v\n", cert.Subject)
					dispatch.PutSessionAttachment(session, "certificate", cert)
				}
				return true
			}

			msgoff += (msglen + 4)
		}
		// skip over the record header and length
		recoff += (reclen + 5)
	}

	return false
}
