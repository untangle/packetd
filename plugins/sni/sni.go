package sni

import (
	"github.com/untangle/packetd/services/dict"
	"github.com/untangle/packetd/services/dispatch"
	"github.com/untangle/packetd/services/logger"
)

var logsrc = "sni"

// PluginStartup function is called to allow plugin specific initialization. We
// increment the argumented WaitGroup so the main process can wait for
// our shutdown function to return during shutdown.
func PluginStartup() {
	logger.LogInfo(logsrc, "PluginStartup(%s) has been called\n", logsrc)
	dispatch.InsertNfqueueSubscription(logsrc, 2, PluginNfqueueHandler)
}

// PluginShutdown function called when the daemon is shutting down. We call Done
// for the argumented WaitGroup to let the main process know we're finished.
func PluginShutdown() {
	logger.LogInfo(logsrc, "PluginShutdown(%s) has been called\n", logsrc)
}

// PluginNfqueueHandler is called to handle nfqueue packet data. We only
// look at traffic with port 443 as destination. When detected, we load
// the server certificate from our cache or fetch it from the server and
// store it in our cache. Once we have the cert, we attach it to the session,
// extract the interesting subject fields, and put them in the session table.
func PluginNfqueueHandler(mess dispatch.TrafficMessage, ctid uint32, newSession bool) dispatch.NfqueueResult {
	var result dispatch.NfqueueResult
	result.Owner = logsrc
	result.PacketMark = 0
	result.SessionRelease = false

	// we only need to search for SNI in TCP traffic going to port 443
	if mess.TCPlayer == nil || mess.Tuple.ServerPort != 443 {
		result.SessionRelease = true
		return result
	}

	// grab the SNI hostname from the client hello
	hostname := extractSNIhostname(mess.Payload)
	if hostname != "" {
		logger.LogDebug(logsrc, "Extracted SNI %s for %d\n", hostname, ctid)
		dict.AddSessionEntry(ctid, "ClientSNI", hostname)
		result.SessionRelease = true
		return result
	}

	return result
}

// This was pulled from https://github.com/polvi/sni/sni.go
func extractSNIhostname(b []byte) string {
	// If the packet is too short to hold a ClientHello just return
	if len(b) < 48 {
		return ""
	}

	rest := b[5:]
	current := 0
	handshakeType := rest[0]
	current++

	if handshakeType != 0x1 {
		logger.LogDebug(logsrc, "Packet does not contain a TLS ClientHello message\n")
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
		logger.LogDebug(logsrc, "Packet does not contain TLS extensions\n")
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
				logger.LogDebug(logsrc, "Extension is not a hostname\n")
				return ""
			}
			nameLen := (int(rest[current]) << 8) + int(rest[current+1])
			current += 2
			hostname = string(rest[current : current+nameLen])
		}

		current += extensionDataLength
	}

	if hostname == "" {
		logger.LogDebug(logsrc, "No SNI hostname detected\n")
		return ""
	}

	return hostname
}
