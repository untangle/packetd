package dispatch

import (
	"github.com/untangle/packetd/services/dict"
	"github.com/untangle/packetd/services/logger"
	"sync"
	"time"
)

// SessionEntry stores details related to a session
type SessionEntry struct {
	SessionID          uint64
	PacketCount        uint64
	ByteCount          uint64
	CreationTime       time.Time
	LastActivityTime   time.Time
	ClientSideTuple    Tuple
	ServerSideTuple    Tuple
	ConntrackConfirmed bool
	EventCount         uint64
	Subs               map[string]SubscriptionHolder
	Attachments        map[string]interface{}
}

var sessionTable map[uint32]*SessionEntry
var sessionMutex sync.Mutex
var sessionIndex uint64

// nextSessionID returns the next sequential session ID value
func nextSessionID() uint64 {
	var value uint64
	sessionMutex.Lock()
	value = sessionIndex
	sessionIndex++

	if sessionIndex == 0 {
		sessionIndex++
	}

	sessionMutex.Unlock()
	return (value)
}

// findSessionEntry searches for an entry in the session table
func findSessionEntry(finder uint32) (*SessionEntry, bool) {
	sessionMutex.Lock()
	entry, status := sessionTable[finder]
	logger.LogTrace("Lookup session ctid %d -> %v\n", finder, status)
	sessionMutex.Unlock()
	return entry, status
}

// insertSessionEntry adds an entry to the session table
func insertSessionEntry(finder uint32, entry *SessionEntry) {
	logger.LogTrace("Insert session ctid %d -> %v\n", finder, entry.ClientSideTuple)
	sessionMutex.Lock()
	sessionTable[finder] = entry
	dict.AddSessionEntry(finder, "session_id", entry.SessionID)
	sessionMutex.Unlock()
}

// removeSessionEntry removes an entry from the session table
func removeSessionEntry(finder uint32) {
	logger.LogTrace("Remove session ctid %d\n", finder)
	sessionMutex.Lock()
	dict.DeleteSession(finder)
	delete(sessionTable, finder)
	sessionMutex.Unlock()
}

// cleanSessionTable cleans the session table by removing stale entries
func cleanSessionTable() {
	nowtime := time.Now()

	for key, val := range sessionTable {
		if (nowtime.Unix() - val.LastActivityTime.Unix()) < 600 {
			continue
		}
		removeSessionEntry(key)
		// This happens in some corner cases
		// such as a session that is blocked we will have a session in the session table
		// but it will never reach the conntrack confirmed state, and thus never
		// get a conntrack new or destroy event
		// as such this will exist in the table until the conntrack ID gets re-used
		// or this happens. Since this is condition is expected, just log as debug
		logger.LogDebug("Removing stale session entry %d %v\n", key, val.ClientSideTuple)
	}
}

// printSessionTable prints the session table
func printSessionTable() {
	sessionMutex.Lock()
	defer sessionMutex.Unlock()
	for k, v := range sessionTable {
		logger.LogDebug("Session[%d] = %s\n", k, v.ClientSideTuple.String())
	}
}
