// Package reporter provides the "reporter" plugin
// The reporter plugin listens to networking events and writes them to the database
package reporter

import (
	"net"
	"time"

	"github.com/untangle/packetd/services/dict"
	"github.com/untangle/packetd/services/dispatch"
	"github.com/untangle/packetd/services/logger"
	"github.com/untangle/packetd/services/reports"
)

const pluginName = "reporter"

// PluginStartup starts the reporter
func PluginStartup() {
	logger.Info("PluginStartup(%s) has been called\n", pluginName)
	dispatch.InsertNfqueueSubscription(pluginName, 1, PluginNfqueueHandler)
	dispatch.InsertConntrackSubscription(pluginName, 1, PluginConntrackHandler)
	dispatch.InsertNetloggerSubscription(pluginName, 1, PluginNetloggerHandler)
}

// PluginShutdown stops the reporter
func PluginShutdown() {
	logger.Info("PluginShutdown(%s) has been called\n", pluginName)
}

// PluginNfqueueHandler handles the first packet of a session
// Logs a new session_new event
func PluginNfqueueHandler(mess dispatch.NfqueueMessage, ctid uint32, newSession bool) dispatch.NfqueueResult {
	var result dispatch.NfqueueResult
	result.SessionRelease = true

	var session *dispatch.Session
	session = mess.Session
	if session == nil {
		logger.Err("Missing session on NFQueue packet!")
		return result
	}
	dispatch.ReleaseSession(session, pluginName)

	// We only care about new sessions
	if !newSession {
		return result
	}

	// this is the first packet so source interface = client interface
	// we don't know the server interface information yet - nfqueue is prerouting
	var localAddress net.IP
	var remoteAddress net.IP

	// if client is on LAN (type 2)
	if session.ClientInterfaceType == 2 {
		localAddress = session.ClientSideTuple.ClientAddress
		// the server may not actually be on a WAN, but we consider it remote if the client is on a LAN
		remoteAddress = session.ClientSideTuple.ServerAddress
	} else {
		remoteAddress = session.ClientSideTuple.ClientAddress
		// the server could in theory be on another WAN (WAN1 -> WAN2 traffic) but it is very unlikely so we consider
		// the local address to be the server
		localAddress = session.ClientSideTuple.ServerAddress
	}
	columns := map[string]interface{}{
		"time_stamp":            time.Now(),
		"session_id":            session.SessionID,
		"ip_protocol":           session.ClientSideTuple.Protocol,
		"client_interface_id":   session.ClientInterfaceID,
		"client_interface_type": session.ClientInterfaceType,
		"local_address":         localAddress.String(),
		"remote_address":        remoteAddress.String(),
		"client_address":        session.ClientSideTuple.ClientAddress.String(),
		"server_address":        session.ClientSideTuple.ServerAddress.String(),
		"client_port":           session.ClientSideTuple.ClientPort,
		"server_port":           session.ClientSideTuple.ServerPort,
	}
	reports.LogEvent(reports.CreateEvent("session_new", "sessions", 1, columns, nil))
	for k, v := range columns {
		session.PutAttachment(k, v)
		if k == "time_stamp" {
			continue
		}
		dict.AddSessionEntry(session.ConntrackID, k, v)
	}
	return result
}

// PluginConntrackHandler receives conntrack events
func PluginConntrackHandler(message int, entry *dispatch.Conntrack) {
	var session *dispatch.Session

	if entry.Session != nil {
		logger.Trace("Conntrack Event: %c %v 0x%08x\n", message, entry.Session.ClientSideTuple, entry.ConnMark)
	}
	session = entry.Session
	if message == 'N' {
		if session != nil {
			columns := map[string]interface{}{
				"session_id": session.SessionID,
			}
			modifiedColumns := map[string]interface{}{
				"client_address_new":    session.ServerSideTuple.ClientAddress.String(),
				"server_address_new":    session.ServerSideTuple.ServerAddress.String(),
				"client_port_new":       session.ServerSideTuple.ClientPort,
				"server_port_new":       session.ServerSideTuple.ServerPort,
				"server_interface_id":   session.ServerInterfaceID,
				"server_interface_type": session.ServerInterfaceType,
			}
			reports.LogEvent(reports.CreateEvent("session_nat", "sessions", 2, columns, modifiedColumns))
			for k, v := range modifiedColumns {
				session.PutAttachment(k, v)
				dict.AddSessionEntry(session.ConntrackID, k, v)
			}

		} else {
			// We should not receive a new conntrack event for something that is not in the session table
			// However it happens on local outbound sessions, we should handle these diffently
			// FIXME log session_new event (bypassed sessions in NGFW)
		}
	}

	if message == 'U' {
		if session != nil {
			doAccounting(entry, session.SessionID, entry.ConntrackID)
		} else {
			// Still account for unknown session data
			doAccounting(entry, 0, entry.ConntrackID)
		}
	}
}

// PluginNetloggerHandler receives NFLOG events
func PluginNetloggerHandler(netlogger *dispatch.NetloggerMessage) {
	// FIXME
	// IMPLEMENT ME
}

// doAccounting does the session_minutes accounting
func doAccounting(entry *dispatch.Conntrack, sessionID uint64, ctid uint32) {
	dict.AddSessionEntry(ctid, "byte_rate", uint32(entry.TotalByteRate))
	dict.AddSessionEntry(ctid, "client_byte_rate", uint32(entry.ClientByteRate))
	dict.AddSessionEntry(ctid, "server_byte_rate", uint32(entry.ServerByteRate))
	dict.AddSessionEntry(ctid, "packet_rate", uint32(entry.TotalPacketRate))
	dict.AddSessionEntry(ctid, "client_packet_rate", uint32(entry.ClientPacketRate))
	dict.AddSessionEntry(ctid, "server_packet_rate", uint32(entry.ServerPacketRate))

	if entry.TotalByteRate != 0 && entry.ClientByteRate != 0 && entry.ServerByteRate != 0 && entry.TotalPacketRate != 0 && entry.ClientPacketRate != 0 && entry.ServerPacketRate != 0 {
		columns := map[string]interface{}{
			"time_stamp":         time.Now(),
			"session_id":         sessionID,
			"client_bytes":       entry.ClientBytesDiff,
			"server_bytes":       entry.ServerBytesDiff,
			"bytes":              entry.TotalBytesDiff,
			"client_byte_rate":   int32(entry.ClientByteRate),
			"server_byte_rate":   int32(entry.ServerByteRate),
			"byte_rate":          int32(entry.TotalByteRate),
			"client_packets":     entry.ClientPacketsDiff,
			"server_packets":     entry.ServerPacketsDiff,
			"packets":            entry.TotalPacketsDiff,
			"client_packet_rate": int32(entry.ClientPacketRate),
			"server_packet_rate": int32(entry.ServerPacketRate),
			"packet_rate":        int32(entry.TotalPacketRate),
		}
		reports.LogEvent(reports.CreateEvent("session_stat", "session_stats", 1, columns, nil))
	}
}
