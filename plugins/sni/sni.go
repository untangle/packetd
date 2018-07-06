package sni

import (
	"github.com/untangle/packetd/services/dict"
	"github.com/untangle/packetd/services/dispatch"
	"github.com/untangle/packetd/services/logger"
)

var logsrc = "sni"

// PluginStartup function is called to allow plugin specific initialization.
func PluginStartup() {
	logger.LogInfo(logsrc, "PluginStartup(%s) has been called\n", logsrc)
	dispatch.InsertNfqueueSubscription(logsrc, 2, PluginNfqueueHandler)
}

// PluginShutdown function called when the daemon is shutting down.
func PluginShutdown() {
	logger.LogInfo(logsrc, "PluginShutdown(%s) has been called\n", logsrc)
}

// PluginNfqueueHandler is called to handle nfqueue packet data. We only
// look at traffic with port 443 as destination. When detected, we look
// for a TLS ClientHello packet from which we extract the SNI hostname
func PluginNfqueueHandler(mess dispatch.NfqueueMessage, ctid uint32, newSession bool) dispatch.NfqueueResult {
	var result dispatch.NfqueueResult
	result.Owner = logsrc
	result.PacketMark = 0
	result.SessionRelease = false

	// we only need to search for SNI in TCP traffic going to port 443
	if mess.TCPlayer == nil || mess.Tuple.ServerPort != 443 {
		result.SessionRelease = true
		return result
	}

	// look for SNI hostname in the packet
	release, hostname := extractSNIhostname(mess.Payload)

	// if we found the hostname write to the dictionary and release the session
	if hostname != "" {
		logger.LogDebug(logsrc, "Extracted SNI %s for %d\n", hostname, ctid)
		dict.AddSessionEntry(ctid, "ssl_sni", hostname)
	}

	// set the session release from the extractor return
	result.SessionRelease = release
	return result
}

/*

This table describes the structure of the TLS ClientHello message:

Size   Description					Offset
----------------------------------------------------------------------
1      Record Content Type			0
2      SSL Version					1
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

*/

func extractSNIhostname(buffer []byte) (bool, string) {
	var hostname string
	var current int
	var maxlen int

	hostname = ""
	maxlen = len(buffer)

	// if the packet is too short to hold a ClientHello just return
	if maxlen < 48 {
		return false, hostname
	}

	// check for the TLS handshake protocol
	if buffer[0] != 0x16 {
		return false, hostname
	}

	// check for SSLv3
	if buffer[1] != 0x03 {
		return false, hostname
	}

	// check for TLS 1.0 or greater
	if buffer[2] < 0x01 {
		return false, hostname
	}

	// check for ClientHello message type
	if buffer[5] != 0x01 {
		return false, hostname
	}

	// adjust the offset to the session ID length field
	current = 43

	/*
	 * If we get to this point we likely have a valid TLS ClientHello packet
	 * so for the rest of the function we return true to release the session
	 */

	// skip over the session ID
	sessionIDLength := int(buffer[current])
	current++
	current += sessionIDLength
	if current >= maxlen {
		return true, hostname
	}

	// skip over the cipher suites
	cipherSuiteLength := (int(buffer[current]) << 8) + int(buffer[current+1])
	current += 2
	current += cipherSuiteLength
	if current >= maxlen {
		return true, hostname
	}

	// skip over the compression methods
	compressionMethodLength := int(buffer[current])
	current++
	current += compressionMethodLength
	if current >= maxlen {
		return true, hostname
	}

	// get the length of all extensions
	extensionsLength := (int(buffer[current]) << 8) + int(buffer[current+1])
	current += 2

	if extensionsLength == 0 {
		return true, hostname
	}

	for current < len(buffer) {
		// get the extension type
		extensionType := (int(buffer[current]) << 8) + int(buffer[current+1])
		current += 2

		// get the extension length
		extensionDataLength := (int(buffer[current]) << 8) + int(buffer[current+1])
		current += 2

		// ignore everything except the server name extension
		if extensionType != 0 {
			current += extensionDataLength
			continue
		}

		// skip the number of names since we assume there is just one, but leave the current offset
		// intact making it easy to skip over the extension if we find something to doesn't make sense
		spot := current + 2

		// get the name type
		nameType := buffer[spot]
		spot++

		// if we found a hostname extract it and break
		if nameType == 0 {
			nameLen := (int(buffer[spot]) << 8) + int(buffer[spot+1])
			spot += 2
			hostname = string(buffer[spot : spot+nameLen])
			break
		}

		current += extensionDataLength
	}

	return true, hostname
}
