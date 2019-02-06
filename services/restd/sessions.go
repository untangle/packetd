package restd

import (
	"net/http"

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

	c.JSON(200, sessions)
}

// getSessions returns the fully merged list of sessions
// as a list of map[string]interface{}
// It reads the session list from /proc/net/nf_conntrack
// and merges in the values for each session in dict
func getSessions() ([]map[string]interface{}, error) {
	var sessions []map[string]interface{}

	conntrackTable := dispatch.GetConntrackTable()

	for _, v := range conntrackTable {
		m := parseConntrack(v)
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

	m["conntrack_id"] = ct.ConntrackID
	m["session_id"] = ct.SessionID
	//m["protocol"] = FIXME
	m["ip_protocol"] = ct.ClientSideTuple.Protocol

	//FIXME get timeout
	//FIXME get tcp conn state
	//FIXME get packet count
	//FIXME get ASSURED/UNREPLIED flags

	m["client_address"] = ct.ClientSideTuple.ClientAddress
	m["client_port"] = ct.ClientSideTuple.ClientPort
	m["server_address"] = ct.ClientSideTuple.ServerAddress
	m["server_port"] = ct.ClientSideTuple.ServerPort
	m["client_address_new"] = ct.ServerSideTuple.ClientAddress
	m["client_port_new"] = ct.ServerSideTuple.ClientPort
	m["server_address_new"] = ct.ServerSideTuple.ServerAddress
	m["server_port_new"] = ct.ServerSideTuple.ServerPort

	m["bytes"] = ct.TotalBytes
	m["c2s_bytes"] = ct.C2SBytes
	m["s2c_bytes"] = ct.S2CBytes

	var mark uint32
	mark = ct.ConnMark
	clientInterfaceID := mark & 0x000000ff
	clientInterfaceType := mark & 0x03000000 >> 24
	serverInterfaceID := mark & 0x0000ff00 >> 8
	serverInterfaceType := mark & 0x0c000000 >> 26
	priority := mark & 0x00ff0000 >> 16

	m["mark"] = mark
	if clientInterfaceID != 0 {
		m["client_interface_id"] = clientInterfaceID
	}
	if clientInterfaceType != 0 {
		m["client_interface_type"] = clientInterfaceType
	}
	if serverInterfaceID != 0 {
		m["server_interface_id"] = serverInterfaceID
	}
	if serverInterfaceType != 0 {
		m["server_interface_type"] = serverInterfaceType
	}
	m["priority"] = priority

	return m
}
