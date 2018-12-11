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
	result.Owner = pluginName
	result.SessionRelease = true

	var session *dispatch.SessionEntry
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
	var clientInterface uint8
	var serverInterface uint8
	var clientIsOnLan bool
	var localAddress net.IP
	var remoteAddress net.IP

	clientInterface = uint8((mess.PacketMark & 0x000000FF))
	serverInterface = uint8((mess.PacketMark & 0x0000FF00) >> 8)
	clientIsOnLan = (((mess.PacketMark & 0x03000000) >> 24) == 2)

	if clientIsOnLan {
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
		"time_stamp":       time.Now(),
		"session_id":       session.SessionID,
		"ip_protocol":      session.ClientSideTuple.Protocol,
		"client_interface": clientInterface,
		"server_interface": serverInterface,
		"local_address":    localAddress.String(),
		"remote_address":   remoteAddress.String(),
		"client_address":   session.ClientSideTuple.ClientAddress.String(),
		"server_address":   session.ClientSideTuple.ServerAddress.String(),
		"client_port":      session.ClientSideTuple.ClientPort,
		"server_port":      session.ClientSideTuple.ServerPort,
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
func PluginConntrackHandler(message int, entry *dispatch.ConntrackEntry) {
	var session *dispatch.SessionEntry

	session = entry.Session
	if message == 'N' {
		if session != nil {
			columns := map[string]interface{}{
				"session_id": session.SessionID,
			}
			modifiedColumns := map[string]interface{}{
				"client_address_new": session.ServerSideTuple.ClientAddress.String(),
				"server_address_new": session.ServerSideTuple.ServerAddress.String(),
				"client_port_new":    session.ServerSideTuple.ClientPort,
				"server_port_new":    session.ServerSideTuple.ServerPort,
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
		// FIXME log session_minutes event
	}
}

// PluginNetloggerHandler receives NFLOG events
func PluginNetloggerHandler(netlogger *dispatch.NetloggerMessage) {
	// FIXME
	// IMPLEMENT ME
}
