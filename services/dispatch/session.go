package dispatch

import (
	"sync"
	"time"

	"github.com/untangle/packetd/services/dict"
	"github.com/untangle/packetd/services/logger"
)

// Session stores information of a packetd session
type Session struct {

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
	Conntrack *Conntrack

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
var sessionTable map[uint32]*Session

// sessionMutex is the lock for sessionTable
var sessionMutex sync.Mutex

// sessionIndex stores the next available unique SessionID
var sessionIndex uint64

// PutAttachment is used to safely add an attachment to a session object
func (sess *Session) PutAttachment(name string, value interface{}) {
	sess.attachmentLock.Lock()
	sess.attachments[name] = value
	sess.attachmentLock.Unlock()
}

// GetAttachment is used to safely get an attachment from a session object
func (sess *Session) GetAttachment(name string) interface{} {
	sess.attachmentLock.Lock()
	value := sess.attachments[name]
	sess.attachmentLock.Unlock()
	return value
}

// DeleteAttachment is used to safely delete an attachment from a session object
func (sess *Session) DeleteAttachment(name string) bool {
	sess.attachmentLock.Lock()
	value := sess.attachments[name]
	delete(sess.attachments, name)
	sess.attachmentLock.Unlock()

	if value == nil {
		return false
	}

	return true
}

// destroy is called to end the session
// it removes the session from the session table, and calls
// the finialization event to all subscribers
func (sess *Session) destroy() {
	sessionMutex.Lock()
	sessInTable, found := sessionTable[sess.ConntrackID]
	if found && sess == sessInTable {
		dict.DeleteSession(sess.ConntrackID)
		delete(sessionTable, sess.ConntrackID)
	}
	sessionMutex.Unlock()
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

// findSession searches for an sess in the session table
func findSession(ctid uint32) *Session {
	sessionMutex.Lock()
	sess, status := sessionTable[ctid]
	logger.Trace("Lookup session index %v -> %v\n", ctid, status)
	sessionMutex.Unlock()
	if status == false {
		return nil
	}
	return sess
}

// insertSessionTable adds an sess to the session table
func insertSessionTable(ctid uint32, sess *Session) {
	logger.Trace("Insert session index %v -> %v\n", ctid, sess.ClientSideTuple)
	sessionMutex.Lock()
	defer sessionMutex.Unlock()
	if sessionTable[ctid] != nil {
		logger.Warn("Overriding previous session: %v\n", ctid)
		delete(sessionTable, ctid)
	}
	sessionTable[ctid] = sess
	dict.AddSessionEntry(sess.ConntrackID, "session_id", sess.SessionID)
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
		if time.Now().Sub(session.LastActivityTime) > 1800*time.Second {
			if session.ConntrackConfirmed {
				logger.Err("Removing stale (%v) session [%v] %v\n", time.Now().Sub(session.LastActivityTime), ctid, session.ClientSideTuple)
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
