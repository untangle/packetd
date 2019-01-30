package restd

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/untangle/packetd/services/dict"
	"github.com/untangle/packetd/services/logger"
)

// statusSessions is the RESTD /api/status/sessions handler
func statusSessions(c *gin.Context) {
	logger.Info("statusSession()\n")

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

	file, err := os.Open("/proc/net/nf_conntrack")
	if err != nil {
		logger.Warn("Failed to open nf_conntrack: %s\n", err.Error())
		return sessions, err
	}
	defer file.Close()

	// build a list of sessions from /proc/net/nf_conntrack
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		m := parseSession(line)
		logger.Warn("LINE: %v\n", m)
		if m != nil {
			sessions = append(sessions, m)
		}
	}

	// build a tuple map to store the sessions
	tupleMap := make(map[string]map[string]interface{})
	for _, s := range sessions {
		tuple := fmt.Sprintf("%v|%v|%v->%v|%v", s["ip_protocol"], s["client_address"], s["client_port"], s["server_address"], s["server_port"])
		tupleMap[tuple] = s
	}

	// read the data from dict "session" table
	sessionTable, err := dict.GetSessions()
	if err != nil {
		logger.Warn("Unable to get sessions: %v\n", err)
	}

	// for all the data in the dict "session" table, merge it into the matching tupleMap entries
	for _, session := range sessionTable {
		tuple := fmt.Sprintf("%v|%v|%v->%v|%v", session["ip_protocol"], session["client_address"], session["client_port"], session["server_address"], session["server_port"])

		_, ok := tupleMap[tuple]
		if !ok {
			// matching session not found, continue
			continue
		}

		// matching session found, merge the (new) values into the map
		for key, value := range session {
			_, alreadyFound := tupleMap[tuple][key]
			if alreadyFound {
				continue
			} else {
				tupleMap[tuple][key] = value
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
func parseSession(line string) map[string]interface{} {
	var err error
	m := make(map[string]interface{})
	i := 0

	words := strings.Fields(line)
	if len(words) < 12 {
		logger.Warn("Too few words (%i). Skipping line: %s\n", len(words), line)
		return nil
	}
	// exclude 127.0.0.1
	if strings.Contains(line, "127.0.0.1") {
		return nil
	}

	// words[0] "ipv4" or "ipv6" usually
	m["protocol"] = words[i]

	//words[1] is network layer protocol
	i++

	//words[2] is transmission layer protocol name "tcp" or "udp"
	i++

	// words[3] is the ip protocol number. usually 6 or 17
	i++
	ipProtocolInt, err := strconv.Atoi(words[i])
	if err != nil {
		logger.Warn("Invalid IP Protocol (%s). Skipping line: %s\n", err.Error(), line)
		return nil
	}
	m["ip_protocol"] = uint8(ipProtocolInt)

	// words[4] is seconds to expire
	i++
	timeoutSeconds, err := strconv.Atoi(words[i])
	if err != nil {
		logger.Warn("Invalid Timeout (%s). Skipping line: %s\n", err.Error(), line)
		return nil
	}
	m["timeout_seconds"] = uint32(timeoutSeconds)

	// words[5] is either a connection state, or the beginning of the key=value pairs
	// check if it looks like key=value, if so start parsing the key=value pairs, otherwise treat it like
	// a connection state
	i++
	if !strings.Contains(words[i], "=") {
		m["connection_state"] = words[i]
		i++
	}

	// parse the pairs of key=value pairs

	// certain keys get seen twice like src=1.2.3.4
	// The first time the key is seen its the original tuple side
	// The second time its seen its the reply tuple side
	srcSeen := false
	dstSeen := false
	sportSeen := false
	dportSeen := false
	for ; i < len(words); i++ {
		word := words[i]

		//skip flag fields like "[ASSURED]"
		if word == "[ASSURED]" {
			m["assured_flag"] = true
			continue
		}
		if word == "[UNREPLIED]" {
			m["unreplied_flag"] = true
			continue
		}

		parts := strings.Split(word, "=")
		if len(parts) != 2 {
			logger.Warn("Invalid key value pair (%s). Skipping line: %s\n", word, line)
			return nil
		}
		key := parts[0]
		value := parts[1]

		switch key {
		case "src":
			if !srcSeen {
				m["client_address"] = net.ParseIP(value)
			} else {
				m["server_address_new"] = net.ParseIP(value)
			}
			srcSeen = true
			break
		case "dst":
			if !dstSeen {
				m["server_address"] = net.ParseIP(value)
			} else {
				m["client_address_new"] = net.ParseIP(value)
			}
			dstSeen = true
			break
		case "sport":
			port, err := strconv.Atoi(value)
			if err != nil {
				logger.Warn("Invalid port (%s). Skipping line: %s\n", err.Error(), line)
				return nil
			}
			if !sportSeen {
				m["client_port"] = uint16(port)
			} else {
				m["server_port_new"] = uint16(port)
			}
			sportSeen = true
			break
		case "dport":
			port, err := strconv.Atoi(value)
			if err != nil {
				logger.Warn("Invalid port (%s). Skipping line: %s\n", err.Error(), line)
				return nil
			}
			if !dportSeen {
				m["server_port"] = uint16(port)
			} else {
				m["client_port_new"] = uint16(port)
			}
			dportSeen = true
			break
		case "packets": //fallthrough
		case "bytes":
			i, err := strconv.Atoi(value)
			if err != nil {
				logger.Warn("Invalid %s (%s). Skipping line: %s\n", key, err.Error(), line)
				return nil
			}
			m[key] = i
		case "mark":
			mark, err := strconv.Atoi(value)
			if err != nil {
				logger.Warn("Invalid mark (%s). Skipping line: %s\n", err.Error(), line)
				return nil
			}
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
		}
	}

	return m
}
