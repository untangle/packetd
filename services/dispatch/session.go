package dispatch

import (
	"sync"
	"time"

	"github.com/untangle/packetd/services/dict"
	"github.com/untangle/packetd/services/logger"
)

// SessionEntry stores information of a packetd session
type SessionEntry struct {

	// SessionID is the globally unique ID for this session (created in packetd)
	SessionID uint64

	// ConntrackID is the conntrack ID. ConntrackIDs (ctid) are unique but reused.
	ConntrackID uint32

	// CreationTime stores the creation time of the session
	CreationTime time.Time

	// LastActivityTime stores the last time we got any nfqueue/conntrack event for this session
	LastActivityTime time.Time

	// ClientSideTuple stores the client-side (pre-NAT) session tuple
	ClientSideTuple Tuple

	// ServerSideTuple stores the server-side (post-NAT) session tuple
	ServerSideTuple Tuple

	// ConntrackConfirmed is true if this session has been confirmed by conntrack. false otherwise
	// A session becomes confirmed by conntrack once its packet reaches the final CONNTRACK_CONFIRM
	// priority in netfilter, and we get an conntrack "NEW" event for it.
	// Packets that never reach this point (blocked packets) often never get confirmed
	ConntrackConfirmed bool

	// The conntrack entry associated with this session
	ConntrackEntry *ConntrackEntry

	// PacketdCount stores the number of packets queued to packetd for this session
	PacketCount uint64

	// ByteCount stores the number of bytes of packets queued to packetd for this session
	ByteCount uint64

	// EventCount stores the number of nfqueue/conntrack events for this session
	EventCount uint64

	// subscriptions stores the nfqueue subscribers
	subscriptions map[string]SubscriptionHolder

	// subLocker is the lock for subscriptions
	subLocker sync.Mutex

	// attachments stores the metadata attachments
	attachments map[string]interface{}

	// attachmentLock is the lock for attachments
	attachmentLock sync.Mutex
}

// sessionTable is the global session table
var sessionTable map[uint32]*SessionEntry

// sessionMutex is the lock for sessionTable
var sessionMutex sync.Mutex

// sessionIndex stores the next available unique SessionID
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
func findSessionEntry(ctid uint32) *SessionEntry {
	sessionMutex.Lock()
	entry, status := sessionTable[ctid]
	logger.Trace("Lookup session index %v -> %v\n", ctid, status)
	sessionMutex.Unlock()
	if status == false {
		return nil
	}
	return entry
}

// insertSessionEntry adds an entry to the session table
func insertSessionEntry(ctid uint32, entry *SessionEntry) {
	logger.Trace("Insert session index %v -> %v\n", ctid, entry.ClientSideTuple)
	sessionMutex.Lock()
	defer sessionMutex.Unlock()
	if sessionTable[ctid] != nil {
		delete(sessionTable, ctid)
	}
	sessionTable[ctid] = entry
	dict.AddSessionEntry(entry.ConntrackID, "session_id", entry.SessionID)
}

// removeSessionEntry removes an entry from the session table
// of the specified ctid
func removeSessionEntry(ctid uint32) {
	logger.Trace("Remove session ctid %v\n", ctid)
	sessionMutex.Lock()
	defer sessionMutex.Unlock()
	entry, status := sessionTable[ctid]
	if status {
		dict.DeleteSession(entry.ConntrackID)
	}
	delete(sessionTable, ctid)
}

// removeSessionEntrySpecific removes an entry from the session table
// of the specified ctid if its mapped to the specified sess
func removeSessionEntrySpecific(sess *SessionEntry) {
	logger.Trace("Remove session ctid %v\n", sess.ConntrackID)
	sessionMutex.Lock()
	defer sessionMutex.Unlock()
	entry, status := sessionTable[sess.ConntrackID]
	if entry == sess {
		if status {
			dict.DeleteSession(entry.ConntrackID)
		}
		delete(sessionTable, sess.ConntrackID)
	}
}

// cleanSessionTable cleans the session table by removing stale entries
func cleanSessionTable() {
	sessionMutex.Lock()
	defer sessionMutex.Unlock()

	for ctid, session := range sessionTable {
		// Having stale sessions is normal if sessions get blocked
		// Their conntracks never get confirmed and thus there is never a delete conntrack event
		// These sessions will hang in the table around and get cleaned up here.
		// However, if we find a a stale conntrack-confirmed session.
		if time.Now().Sub(session.LastActivityTime) > 600*time.Second {
			if session.ConntrackConfirmed {
				logger.Err("Removing stale (%v) session entry [%v] %v\n", time.Now().Sub(session.LastActivityTime), ctid, session.ClientSideTuple)
			}
			dict.DeleteSession(ctid)
			delete(sessionTable, ctid)
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
