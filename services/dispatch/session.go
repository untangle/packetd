package dispatch

import (
	"sync"
	"time"

	"github.com/untangle/packetd/services/dict"
	"github.com/untangle/packetd/services/logger"
)

// SessionEntry stores details related to a session
type SessionEntry struct {
	SessionID          uint64
	ConntrackID        uint32
	PacketCount        uint64
	ByteCount          uint64
	CreationTime       time.Time
	LastActivityTime   time.Time
	ClientSideTuple    Tuple
	ServerSideTuple    Tuple
	ConntrackConfirmed bool
	EventCount         uint64
	subscriptions      map[string]SubscriptionHolder
	subLocker          sync.Mutex
	attachments        map[string]interface{}
	attachmentLock     sync.Mutex
}

var sessionTable map[uint32]*SessionEntry
var sessionMutex sync.Mutex
var sessionIndex uint64

// PutAttachment is used to safely add an attachment to a session object
func (entry *SessionEntry) PutAttachment(name string, value interface{}) {
	entry.attachmentLock.Lock()
	entry.attachments[name] = value
	entry.attachmentLock.Unlock()
}

// GetAttachment is used to safely get an attachment from a session object
func (entry *SessionEntry) GetAttachment(name string) interface{} {
	entry.attachmentLock.Lock()
	value := entry.attachments[name]
	entry.attachmentLock.Unlock()
	return value
}

// DeleteAttachment is used to safely delete an attachment from a session object
func (entry *SessionEntry) DeleteAttachment(name string) bool {
	entry.attachmentLock.Lock()
	value := entry.attachments[name]
	delete(entry.attachments, name)
	entry.attachmentLock.Unlock()

	if value == nil {
		return false
	}

	return true
}

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
func findSessionEntry(finder uint32) *SessionEntry {
	sessionMutex.Lock()
	entry, status := sessionTable[finder]
	logger.Trace("Lookup session index %v -> %v\n", finder, status)
	sessionMutex.Unlock()
	if status == false {
		return nil
	}
	return entry
}

// insertSessionEntry adds an entry to the session table
func insertSessionEntry(finder uint32, entry *SessionEntry) {
	logger.Trace("Insert session index %v -> %v\n", finder, entry.ClientSideTuple)
	sessionMutex.Lock()
	defer sessionMutex.Unlock()
	if sessionTable[finder] != nil {
		delete(sessionTable, finder)
	}
	sessionTable[finder] = entry
	dict.AddSessionEntry(entry.ConntrackID, "session_id", entry.SessionID)
}

// removeSessionEntry removes an entry from the session table
func removeSessionEntry(finder uint32) {
	logger.Trace("Remove session index %v\n", finder)
	sessionMutex.Lock()
	defer sessionMutex.Unlock()
	entry, status := sessionTable[finder]
	if status {
		dict.DeleteSession(entry.ConntrackID)
	}
	delete(sessionTable, finder)
}

// cleanSessionTable cleans the session table by removing stale entries
func cleanSessionTable() {
	nowtime := time.Now()

	for key, val := range sessionTable {
		if (nowtime.Unix() - val.LastActivityTime.Unix()) < 600 {
			continue
		}
		removeSessionEntry(key)
		// Having stale sessions is normal if sessions get blocked
		// Their conntracks never get confirmed and thus there is never a delete conntrack event
		// These sessions will hang in the table around and get cleaned up here.

		// However, if we find a a stale conntrack-confirmed session. There is likel an issue
		if val.ConntrackConfirmed {
			logger.Warn("Removing confirmed stale session entry %v %v\n", key, val.ClientSideTuple)
		}
	}
}

// printSessionTable prints the session table
func printSessionTable() {
	sessionMutex.Lock()
	defer sessionMutex.Unlock()
	for k, v := range sessionTable {
		logger.Debug("Session[%v] = %s\n", k, v.ClientSideTuple.String())
	}
}
