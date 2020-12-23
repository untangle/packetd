// Package reporter provides the "reporter" plugin
// The reporter plugin listens to networking events and writes them to the database
package reporter

import (
	"encoding/json"
	"net"
	"time"

	"github.com/untangle/golang-shared/services/logger"
	sse "github.com/untangle/golang-shared/structs/protocolbuffers/SessionStatsEvent"
	"github.com/untangle/packetd/services/dict"
	"github.com/untangle/packetd/services/dispatch"
	"github.com/untangle/packetd/services/reports"
)

const pluginName = "reporter"

// PluginStartup starts the reporter
func PluginStartup() {
	logger.Info("PluginStartup(%s) has been called\n", pluginName)
	dispatch.InsertNfqueueSubscription(pluginName, dispatch.ReporterPriority, PluginNfqueueHandler)
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
	if session.GetClientInterfaceType() == 2 {
		localAddress = session.GetClientSideTuple().ClientAddress
		// the server may not actually be on a WAN, but we consider it remote if the client is on a LAN
		remoteAddress = session.GetClientSideTuple().ServerAddress
	} else {
		remoteAddress = session.GetClientSideTuple().ClientAddress
		// the server could in theory be on another WAN (WAN1 -> WAN2 traffic) but it is very unlikely so we consider
		// the local address to be the server
		localAddress = session.GetClientSideTuple().ServerAddress
	}
	clientSideTuple := session.GetClientSideTuple()

	tStamp := time.Now()

	columns := map[string]interface{}{
		"time_stamp":            tStamp,
		"session_id":            session.GetSessionID(),
		"ip_protocol":           clientSideTuple.Protocol,
		"client_interface_id":   session.GetClientInterfaceID(),
		"client_interface_type": session.GetClientInterfaceType(),
		"local_address":         localAddress,
		"remote_address":        remoteAddress,
		"client_address":        clientSideTuple.ClientAddress,
		"server_address":        clientSideTuple.ServerAddress,
		"client_port":           clientSideTuple.ClientPort,
		"server_port":           clientSideTuple.ServerPort,
		"family":                session.GetFamily(),
	}
	for k, v := range columns {
		session.PutAttachment(k, v)
		if k == "time_stamp" {
			continue
		}
		dict.AddSessionEntry(session.GetConntrackID(), k, v)
	}

	// After sending to dict, switch the time_stamp and address type columns for sending to reportd
	columns["time_stamp"] = tStamp.UnixNano() / 1e6
	columns["local_address"] = localAddress.String()
	columns["remote_address"] = remoteAddress.String()
	columns["client_address"] = clientSideTuple.ClientAddress.String()
	columns["server_address"] = clientSideTuple.ServerAddress.String()

	reports.LogEvent(reports.CreateEvent("session_new", "sessions", 1, columns, nil))

	return result
}

// PluginConntrackHandler receives conntrack events
func PluginConntrackHandler(message int, entry *dispatch.Conntrack) {
	var session *dispatch.Session

	entry.Guardian.RLock()
	defer entry.Guardian.RUnlock()

	if entry.Session != nil {
		logger.Trace("Conntrack Event: %c %v 0x%08x\n", message, entry.Session.GetClientSideTuple(), entry.ConnMark)
	}
	session = entry.Session
	if message == 'N' {
		if session != nil {
			columns := map[string]interface{}{
				"session_id": session.GetSessionID(),
			}
			serverSideTuple := session.GetServerSideTuple()
			modifiedColumns := map[string]interface{}{
				"client_address_new":    serverSideTuple.ClientAddress,
				"server_address_new":    serverSideTuple.ServerAddress,
				"client_port_new":       serverSideTuple.ClientPort,
				"server_port_new":       serverSideTuple.ServerPort,
				"server_interface_id":   session.GetServerInterfaceID(),
				"server_interface_type": session.GetServerInterfaceType(),
			}
			for k, v := range modifiedColumns {
				session.PutAttachment(k, v)
				dict.AddSessionEntry(session.GetConntrackID(), k, v)
			}

			// After sending to dict, switch the time_stamp and address type columns for sending to reportd
			modifiedColumns["client_address_new"] = serverSideTuple.ClientAddress.String()
			modifiedColumns["server_address_new"] = serverSideTuple.ServerAddress.String()

			reports.LogEvent(reports.CreateEvent("session_nat", "sessions", 2, columns, modifiedColumns))

		} else {
			// We should not receive a new conntrack event for something that is not in the session table
			// However it happens on local outbound sessions, we should handle these diffently
			// FIXME log session_new event (bypassed sessions in NGFW)
		}
	}

	if message == 'U' {
		if session != nil {
			doAccounting(entry, session.GetSessionID(), entry.ConntrackID)
		} else {
			// Still account for unknown session data
			doAccounting(entry, 0, entry.ConntrackID)
		}
	}
}

// TrafficEvent defines the prefix passed in Netlogger events
type TrafficEvent struct {
	Type   string
	Table  string
	Chain  string
	RuleID int
	Action string
	Policy int
}

// PluginNetloggerHandler receives NFLOG events
func PluginNetloggerHandler(netlogger *dispatch.NetloggerMessage) {
	var traffic TrafficEvent

	if netlogger.Sessptr == nil {
		logger.Debug("Missing session in netlogger event: %v\n", netlogger)
		return
	}

	columns := map[string]interface{}{
		"session_id": netlogger.Sessptr.GetSessionID(),
	}

	// extract the details from the json passed in the prefix
	json.Unmarshal([]byte(netlogger.Prefix), &traffic)

	// we currently only care about wan routing rules
	if traffic.Type != "rule" || traffic.Table != "wan-routing" {
		return
	}

	modifiedColumns := make(map[string]interface{})
	if traffic.Chain != "" {
		modifiedColumns["wan_rule_chain"] = traffic.Chain
	}
	if traffic.RuleID != 0 {
		modifiedColumns["wan_rule_id"] = traffic.RuleID
	}
	if traffic.Policy != 0 {
		modifiedColumns["wan_policy_id"] = traffic.Policy
	}

	reports.LogEvent(reports.CreateEvent("reporter_netlogger", "sessions", 2, columns, modifiedColumns))
	logger.Debug("NetLogger event for %v: %v\n", columns, modifiedColumns)
}

// doAccounting does the session_minutes accounting
func doAccounting(entry *dispatch.Conntrack, sessionID int64, ctid uint32) {
	dict.AddSessionEntry(ctid, "byte_rate", uint32(entry.TotalByteRate))
	dict.AddSessionEntry(ctid, "client_byte_rate", uint32(entry.ClientByteRate))
	dict.AddSessionEntry(ctid, "server_byte_rate", uint32(entry.ServerByteRate))
	dict.AddSessionEntry(ctid, "packet_rate", uint32(entry.TotalPacketRate))
	dict.AddSessionEntry(ctid, "client_packet_rate", uint32(entry.ClientPacketRate))
	dict.AddSessionEntry(ctid, "server_packet_rate", uint32(entry.ServerPacketRate))

	// if no session traffic detected skip the database insert
	if entry.TotalByteRate == 0 && entry.ClientByteRate == 0 && entry.ServerByteRate == 0 && entry.TotalPacketRate == 0 && entry.ClientPacketRate == 0 && entry.ServerPacketRate == 0 {
		return
	}

	statsEvent := &sse.SessionStatsEvent{}
	statsEvent.TimeStamp = time.Now().UnixNano() / 1000000
	statsEvent.SessionID = sessionID
	statsEvent.Bytes = entry.TotalBytesDiff
	statsEvent.ByteRate = entry.TotalByteRate
	statsEvent.ClientBytes = entry.ClientBytesDiff
	statsEvent.ServerBytes = entry.ServerBytesDiff
	statsEvent.ClientByteRate = entry.ClientByteRate
	statsEvent.ServerByteRate = entry.ServerByteRate
	statsEvent.Packets = entry.TotalPacketsDiff
	statsEvent.ClientPackets = entry.ClientPacketsDiff
	statsEvent.ServerPackets = entry.ServerPacketsDiff
	statsEvent.PacketRate = entry.TotalPacketRate
	statsEvent.ClientPacketRate = entry.ClientPacketRate
	statsEvent.ServerPacketRate = entry.ServerPacketRate

	// send the session_stats data to the database
	reports.LogSessionStats(statsEvent)
}
