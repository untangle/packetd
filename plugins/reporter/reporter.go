// Package reporter provides the "reporter" plugin
// The reporter plugin listens to networking events and writes them to the database
package reporter

import (
	"github.com/untangle/packetd/services/dispatch"
	"github.com/untangle/packetd/services/logger"
	"github.com/untangle/packetd/services/reports"
)

var logsrc = "reporter"

// PluginStartup starts the reporter
func PluginStartup() {
	logger.LogMessage(logger.LogInfo, logsrc, "PluginStartup(%s) has been called\n", logsrc)
	dispatch.InsertNfqueueSubscription(logsrc, 1, PluginNfqueueHandler)
	dispatch.InsertConntrackSubscription(logsrc, 1, PluginConntrackHandler)
	dispatch.InsertNetloggerSubscription(logsrc, 1, PluginNetloggerHandler)
}

// PluginShutdown stops the reporter
func PluginShutdown() {
	logger.LogMessage(logger.LogInfo, logsrc, "PluginShutdown(%s) has been called\n", logsrc)
}

// PluginNfqueueHandler receives a TrafficMessage which includes a Tuple and
// a gopacket.Packet, along with the IP and TCP or UDP layer already extracted.
// We do whatever we like with the data, and when finished, we return an
// integer via the argumented channel with any bits set that we want added to
// the packet mark.
func PluginNfqueueHandler(mess dispatch.TrafficMessage, ctid uint, newSession bool) dispatch.NfqueueResult {
	var result dispatch.NfqueueResult
	result.Owner = logsrc
	result.SessionRelease = true
	result.PacketMark = 0

	// We only care about new sessions
	if !newSession {
		return result
	}

	var session *dispatch.SessionEntry

	session = mess.Session
	if session == nil {
		logger.LogMessage(logger.LogErr, logsrc, "Missing session on NFQueue packet!")
		return result
	}

	// FIXME time_stamp
	// FIXME local_addr
	// FIXME remote_addr
	// FIXME client_intf
	// FIXME server_intf
	columns := map[string]interface{}{
		"session_id":  session.SessionID,
		"ip_protocol": session.ClientSideTuple.Protocol,
		"client_addr": session.ClientSideTuple.ClientAddr,
		"server_addr": session.ClientSideTuple.ServerAddr,
		"client_port": session.ClientSideTuple.ClientPort,
		"server_port": session.ClientSideTuple.ServerPort,
	}
	// FIXME move to logger plugin
	reports.LogEvent(reports.CreateEvent("session_new", "sessions", 1, columns, nil))

	return result
}

// PluginConntrackHandler receives conntrack events
func PluginConntrackHandler(message int, entry *dispatch.ConntrackEntry) {
	var session *dispatch.SessionEntry

	session = entry.Session
	if message == 'N' {
		if session != nil {
			columns := map[string]interface{}{
				"session_id": session.SessionID,
			}
			modifiedColumns := map[string]interface{}{
				"client_addr_new": session.ServerSideTuple.ClientAddr,
				"server_addr_new": session.ServerSideTuple.ServerAddr,
				"client_port_new": session.ServerSideTuple.ClientPort,
				"server_port_new": session.ServerSideTuple.ServerPort,
			}
			// FIXME move to logger plugin
			reports.LogEvent(reports.CreateEvent("session_nat", "sessions", 2, columns, modifiedColumns))
		} else {
			// We should not receive a new conntrack event for something that is not in the session table
			// However it happens on local outbound sessions, we should handle these diffently
			// FIXME log session_new event (bypassed sessions in NGFW)
		}
	}

	if message == 'U' {
		// FIXME log session_minutes event
	}
}

// PluginNetloggerHandler receives NFLOG events
func PluginNetloggerHandler(netlogger *dispatch.NetloggerMessage) {
	// FIXME
	// IMPLEMENT ME
}
