package restd

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/untangle/packetd/services/dict"
	"github.com/untangle/packetd/services/dispatch"
	"github.com/untangle/packetd/services/logger"
)

// statusSessions is the RESTD /api/status/sessions handler
func statusSessions(c *gin.Context) {
	logger.Debug("statusSession()\n")

	sessions, err := getSessions()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}

	c.JSON(http.StatusOK, sessions)
}

// getSessions returns the fully merged list of sessions
// as a list of map[string]interface{}
// It reads the session list from /proc/net/nf_conntrack
// and merges in the values for each session in dict
func getSessions() ([]map[string]interface{}, error) {
	var sessions []map[string]interface{}

	conntrackTable := dispatch.GetConntrackTable()

	for _, v := range conntrackTable {
		v.Guardian.RLock()
		m := parseConntrack(v)
		v.Guardian.RUnlock()
		if m != nil {
			sessions = append(sessions, m)
		}
	}

	// build a tuple map to store the sessions
	tupleMap := make(map[uint32]map[string]interface{})
	for _, s := range sessions {
		var ctidx interface{} = s["conntrack_id"]
		ctid, ok := ctidx.(uint32)
		if !ok {
			logger.Warn("Invalid conntrack_id type: %T\n", ctidx)
			continue
		}
		if ctid == 0 {
			logger.Warn("Invalid conntrack_id: %d\n", ctid)
			continue
		}
		tupleMap[ctid] = s
	}

	// read the data from dict "sessions" table
	sessionTable, err := dict.GetSessions()
	if err != nil {
		logger.Warn("Unable to get sessions: %v\n", err)
	}

	// for all the data in the dict "sessions" table, merge it into the matching tupleMap entries
	for ctid, session := range sessionTable {
		_, ok := tupleMap[ctid]
		if !ok {
			// matching session not found, continue
			continue
		}

		// matching session found, merge the (new) values into the map
		for key, value := range session {
			_, alreadyFound := tupleMap[ctid][key]
			if alreadyFound {
				continue
			} else {
				tupleMap[ctid][key] = value
			}
		}
	}

	// return all the merged values from the tupleMap
	var sessionList []map[string]interface{}
	for _, v := range tupleMap {
		sessionList = append(sessionList, v)
	}

	return sessionList, nil
}

// parse a line of /proc/net/nf_conntrack and return the info in a map
func parseConntrack(ct *dispatch.Conntrack) map[string]interface{} {
	m := make(map[string]interface{})

	// ignore 127.0.0.1 traffic
	if ct.ClientSideTuple.ClientAddress != nil && ct.ClientSideTuple.ClientAddress.String() == "127.0.0.1" {
		return nil
	}
	if ct.ClientSideTuple.ServerAddress != nil && ct.ClientSideTuple.ServerAddress.String() == "127.0.0.1" {
		return nil
	}
	if ct.ClientSideTuple.ClientAddress != nil && ct.ClientSideTuple.ClientAddress.String() == "::1" {
		return nil
	}
	if ct.ClientSideTuple.ServerAddress != nil && ct.ClientSideTuple.ServerAddress.String() == "::1" {
		return nil
	}

	m["conntrack_id"] = uint(ct.ConntrackID)
	m["session_id"] = uint(ct.SessionID)
	m["family"] = uint(ct.Family)
	m["ip_protocol"] = uint(ct.ClientSideTuple.Protocol)

	m["timeout_seconds"] = uint(ct.TimeoutSeconds)
	m["tcp_state"] = uint(ct.TCPState)

	m["client_address"] = uint(ct.ClientSideTuple.ClientAddress)
	m["client_port"] = uint(ct.ClientSideTuple.ClientPort)
	m["server_address"] = uint(ct.ClientSideTuple.ServerAddress)
	m["server_port"] = uint(ct.ClientSideTuple.ServerPort)
	m["client_address_new"] = uint(ct.ServerSideTuple.ClientAddress)
	m["client_port_new"] = uint(ct.ServerSideTuple.ClientPort)
	m["server_address_new"] = uint(ct.ServerSideTuple.ServerAddress)
	m["server_port_new"] = uint(ct.ServerSideTuple.ServerPort)

	m["bytes"] = uint(ct.TotalBytes)
	m["client_bytes"] = uint(ct.ClientBytes)
	m["server_bytes"] = uint(ct.ServerBytes)
	m["packets"] = uint(ct.TotalPackets)
	m["client_packets"] = uint(ct.ClientPackets)
	m["server_packets"] = uint(ct.ServerPackets)

	m["timestamp_start"] = uint(ct.TimestampStart)
	if ct.TimestampStart != 0 {
		m["age_milliseconds"] = uint((uint64(time.Now().UnixNano()) - ct.TimestampStart) / 1000000)
	}

	var mark uint32
	mark = ct.ConnMark
	clientInterfaceID := mark & 0x000000ff
	clientInterfaceType := mark & 0x03000000 >> 24
	serverInterfaceID := mark & 0x0000ff00 >> 8
	serverInterfaceType := mark & 0x0c000000 >> 26
	priority := mark & 0x00ff0000 >> 16
	m["mark"] = uint(mark)
	m["client_interface_id"] = uint(clientInterfaceID)
	m["client_interface_type"] = uint(clientInterfaceType)
	m["server_interface_id"] = uint(serverInterfaceID)
	m["server_interface_type"] = uint(serverInterfaceType)
	m["priority"] = uint(priority)

	return m
}
