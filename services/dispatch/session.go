package dispatch

import (
	"sync"
	"sync/atomic"
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

	// ClientSideInterfaceIndex stores the client-side interface index
	ClientInterfaceID uint8

	// ClientSideInterfaceType stores the client-side interface type
	ClientInterfaceType uint8

	// ServerSideTuple stores the server-side (post-NAT) session tuple
	ServerSideTuple Tuple

	// ServerSideInterfaceIndex stores the server-side interface index
	ServerInterfaceID uint8

	// ServerSideInterfaceType stores the server-side interface type
	ServerInterfaceType uint8

	// ConntrackConfirmed is true if this session has been confirmed by conntrack. false otherwise
	// A session becomes confirmed by conntrack once its packet reaches the final CONNTRACK_CONFIRM
	// priority in netfilter, and we get an conntrack "NEW" event for it.
	// Packets that never reach this point (blocked packets) often never get confirmed
	ConntrackConfirmed bool

	// The conntrack entry associated with this session
	Conntrack *Conntrack

	// subscriptions stores the nfqueue subscribers
	subscriptions map[string]SubscriptionHolder

	// subLocker is the lock for subscriptions
	subLocker sync.Mutex

	// attachments stores the metadata attachments
	attachments map[string]interface{}

	// attachmentLock is the lock for attachments
	attachmentLock sync.Mutex

	packetCount uint64
	byteCount   uint64
	eventCount  uint64
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

// LockAttachments locks the attatchments mutex and returns the attachment map to the caller
func (sess *Session) LockAttachments() map[string]interface{} {
	sess.attachmentLock.Lock()
	return (sess.attachments)
}

// UnlockAttachments unlocks the attachments mutex
func (sess *Session) UnlockAttachments() {
	sess.attachmentLock.Unlock()
}

// GetPacketCount gets the packet count
func (sess *Session) GetPacketCount() uint64 {
	return atomic.LoadUint64(&sess.packetCount)
}

// SetPacketCount sets the packet count
func (sess *Session) SetPacketCount(value uint64) uint64 {
	atomic.StoreUint64(&sess.packetCount, value)
	return value
}

// AddPacketCount increases the packet count by the argumented value
func (sess *Session) AddPacketCount(value uint64) uint64 {
	return atomic.AddUint64(&sess.packetCount, value)
}

// GetByteCount gets the byte count
func (sess *Session) GetByteCount() uint64 {
	return atomic.LoadUint64(&sess.byteCount)
}

// SetByteCount sets the byte count
func (sess *Session) SetByteCount(value uint64) uint64 {
	atomic.StoreUint64(&sess.byteCount, value)
	return value
}

// AddByteCount increases the byte count by the argumented value
func (sess *Session) AddByteCount(value uint64) uint64 {
	return atomic.AddUint64(&sess.byteCount, value)
}

// GetEventCount gets the event count
func (sess *Session) GetEventCount() uint64 {
	return atomic.LoadUint64(&sess.eventCount)
}

// SetEventCount sets the event count
func (sess *Session) SetEventCount(value uint64) uint64 {
	atomic.StoreUint64(&sess.eventCount, value)
	return value
}

// AddEventCount increases the event count by the argumented value
func (sess *Session) AddEventCount(value uint64) uint64 {
	return atomic.AddUint64(&sess.eventCount, value)
}

// removeFromSessionTable removes the session from the session table
// it does a sanity check to make sure the session in question
// is actually in the table
func (sess *Session) removeFromSessionTable() {
	sessionMutex.Lock()
	sessInTable, found := sessionTable[sess.ConntrackID]
	if found && sess == sessInTable {
		delete(sessionTable, sess.ConntrackID)
	}
	sessionMutex.Unlock()
}

// flushDict flushes the dict for the session
// it does a sanity check to make sure it ows its ctid
// by doing a lookup in the session table
func (sess *Session) flushDict() {
	sessionMutex.Lock()
	sessInTable, found := sessionTable[sess.ConntrackID]
	if found && sess == sessInTable {
		dict.DeleteSession(sess.ConntrackID)
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
		// However, if we find a a stale conntrack-confirmed session that is bad.

		// We use 10000 seconds because 7440 is the established idle tcp timeout default
		if time.Now().Sub(session.LastActivityTime) > 10000*time.Second {
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
