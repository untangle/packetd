// Package reporter provides the "reporter" plugin
// The reporter plugin listens to networking events and writes them to the database
package reporter

import (
	"encoding/json"
	"net"
	"sync"
	"time"

	"github.com/untangle/packetd/services/dict"
	"github.com/untangle/packetd/services/dispatch"
	"github.com/untangle/packetd/services/logger"
	"github.com/untangle/packetd/services/reports"
	"github.com/untangle/packetd/services/settings"
)

const pluginName = "reporter"

var rulesLookup = make(map[string]string)
var rulesLookupMutex sync.RWMutex
var policiesLookup = make(map[string]string)
var policiesLookupMutex sync.RWMutex

// PluginStartup starts the reporter
func PluginStartup() {
	logger.Info("PluginStartup(%s) has been called\n", pluginName)
	loadRules()
	loadPolicies()
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
	columns := map[string]interface{}{
		"time_stamp":            time.Now(),
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
	reports.LogEvent(reports.CreateEvent("session_new", "sessions", 1, columns, nil))
	for k, v := range columns {
		session.PutAttachment(k, v)
		if k == "time_stamp" {
			continue
		}
		dict.AddSessionEntry(session.GetConntrackID(), k, v)
	}
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
			reports.LogEvent(reports.CreateEvent("session_nat", "sessions", 2, columns, modifiedColumns))
			for k, v := range modifiedColumns {
				session.PutAttachment(k, v)
				dict.AddSessionEntry(session.GetConntrackID(), k, v)
			}

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
	RuleID string
	Action string
	Policy string
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

	// load the full GUIDs for rules/policies using the first 8 bytes from the UUID
	traffic.RuleID = getFullID(traffic.RuleID, rulesLookup, &rulesLookupMutex, loadRules)
	traffic.Policy = getFullID(traffic.Policy, policiesLookup, &policiesLookupMutex, loadPolicies)

	modifiedColumns := make(map[string]interface{})
	if traffic.Chain != "" {
		modifiedColumns["wan_rule_chain"] = traffic.Chain
	}
	if traffic.RuleID != "" {
		modifiedColumns["wan_rule_id"] = traffic.RuleID
	}
	if traffic.Policy != "" {
		modifiedColumns["wan_policy_id"] = traffic.Policy
	}

	reports.LogEvent(reports.CreateEvent("reporter_netlogger", "sessions", 2, columns, modifiedColumns))
	logger.Debug("NetLogger event for %v: %v\n", columns, modifiedColumns)
}

// getFullID retrieves the full GUID from a lookupMap using the first 8 bytes of the GUID
// param idLookup (string) - the ID to use as a lookup
// param lookupMap (map[string]string) - the lookup map containing all the guids
// param lookupMutex (*sync.RWMutex) - the mutex for controlling write access to the lookup map
// param reloadFunc (func()) - the function to call in the case that we want to try and reload data in the lookupMap from settings
func getFullID(idLookup string, lookupMap map[string]string, lookupMutex *sync.RWMutex, reloadFunc func()) string {
	fullID := idLookup

	// These indicate cache so just return them
	if fullID == "-2" || fullID == "-1" {
		return fullID
	}

	// look it up in the hash set
	lookupMutex.RLock()
	fullID = lookupMap[fullID]
	lookupMutex.RUnlock()

	// if not found, reload and look it up (just in case)
	if fullID == idLookup || fullID == "" {
		logger.Debug("ID %s cannot be found, calling reloadFunc (%s) to find it. \n", fullID, reloadFunc)
		reloadFunc()
		lookupMutex.RLock()
		fullID = lookupMap[fullID]
		lookupMutex.RUnlock()
	}
	return fullID
}

// loadRules will load the WAN rule GUIDs from settings into the rulesLookup Map
func loadRules() {
	wanChainsIntf, err := settings.GetCurrentSettings([]string{"wan", "policy_chains"})

	if err != nil {
		logger.Warn("Unable to load wan rules: %s", err)
		return
	}

	wanRuleChainMap, ok := wanChainsIntf.([]interface{})
	if !ok {
		logger.Warn("Unable to load rule chain map: %s", err)
		return
	}

	for _, ruleChain := range wanRuleChainMap {
		ruleChainInfo, ok := ruleChain.(map[string]interface{})

		if !ok {
			logger.Warn("Invalid rule chain in settings: %T\n", ruleChain)
			continue
		}
		if ruleChainInfo == nil {
			logger.Warn("nil rule chain in interface list\n")
			continue
		}

		ruleMap, ok := ruleChainInfo["rules"].([]interface{})

		if !ok {
			logger.Warn("Invalid rule chain in settings: %T\n", ruleChain)
			continue
		}

		for _, rules := range ruleMap {
			ruleInfo, ok := rules.(map[string]interface{})

			if !ok {
				logger.Warn("Invalid rule in rule-chain: %T\n", ruleChain)
				continue
			}
			if ruleInfo == nil {
				logger.Warn("nil rule chain in interface list\n")
				continue
			}

			logger.Debug("Rule Info being added to lookup map: %s\n", ruleInfo)

			buildGUIDLookup("ruleId", ruleInfo, rulesLookup, &rulesLookupMutex)
		}
	}

}

// loadPolicies will load the WAN policy GUIDs from settings into the policiesLookup map
func loadPolicies() {
	wanPoliciesintf, err := settings.GetCurrentSettings([]string{"wan", "policies"})

	if err != nil {
		logger.Warn("Unable to load wan policies: %s", err)
		return
	}

	wanPolicyMap, ok := wanPoliciesintf.([]interface{})

	if !ok {
		logger.Warn("Unable to load wan policies: %s", err)
		return
	}

	for _, policy := range wanPolicyMap {
		policyInfo, ok := policy.(map[string]interface{})
		if !ok {
			logger.Warn("Invalid policy in settings: %T\n", policy)
			continue
		}
		if policyInfo == nil {
			logger.Warn("nil policy in interface list\n")
			continue
		}

		logger.Debug("WAN Policy being added to lookup map: %s \n", policyInfo)

		buildGUIDLookup("policyId", policyInfo, policiesLookup, &policiesLookupMutex)

	}
}

// buildGUIDLookup is used to build the lookupMap passed as a parameter. The lookupMap will be locked with the lookupMutex
// and the idName and idInfo are used to get the GUID based on the first 8 digits of the GUID
// param idName (String) - the ID Name to lookup in the info map
// param idInfo (map[string]inteface{}) - the IDInfo container that contains the ID
// param lookupMap (map[string]string) - the GUID Lookup map to store the 8 digit guid relation with the full GUID
// param lookupMutex (*symc.RWMutex) - the locking mutex for locking access to the lookupMap
func buildGUIDLookup(idName string, idInfo map[string]interface{}, lookupMap map[string]string, lookupMutex *sync.RWMutex) {
	idRune := []rune(idInfo[idName].(string))
	lookupMutex.Lock()
	defer lookupMutex.Unlock()
	lookupMap[string(idRune[0:8])] = string(idRune)
}

// doAccounting does the session_minutes accounting
func doAccounting(entry *dispatch.Conntrack, sessionID int64, ctid uint32) {
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
