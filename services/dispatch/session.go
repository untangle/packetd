package dispatch

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/untangle/packetd/services/dict"
	"github.com/untangle/packetd/services/logger"
	"github.com/untangle/packetd/services/overseer"
)

// Session stores information about a packetd session
// All fields are private and must be access with the get and set functions
// defined below to ensure there are no data races
type Session struct {

	/*
		***** WARNING - WARNING - WARNING - WARNING - WARNING *****

		There is an issue with atomic operations on 64 bit values on
		ARM platforms that can cause an exeception when values are not
		64 bit aligned.

		On both ARM and x86-32, it is the caller's responsibility to arrange
		for 64-bit alignment of 64-bit words accessed atomically. The first
		word in a variable or in an allocated struct, array, or slice can
		be relied upon to be 64-bit aligned.

		It is for that reason we put all of the 64 bit values at the top.

		https://github.com/golang/go/issues/23345
	*/

	// sessionID is the globally unique ID for this session (created in packetd)
	sessionID int64

	// used to keep track of the session packet, byte, event, and navl counts
	packetCount uint64
	byteCount   uint64
	eventCount  uint64
	navlCount   uint64

	// conntrackID is the conntrack ID. ConntrackIDs (ctid) are unique but reused.
	conntrackID uint32

	// creationTime stores the creation time of the session
	creationTime time.Time
	creationLock sync.RWMutex

	// clientSideTuple stores the client-side (pre-NAT) session tuple
	clientSideTuple Tuple
	clientSideLock  sync.RWMutex

	// serverSideTuple stores the server-side (post-NAT) session tuple
	serverSideTuple Tuple
	serverSideLock  sync.RWMutex

	// stores the client and server side interface index and type using int32 because the atomic
	// package doesn't have anything smaller but the get and set take and return them as uint8
	clientInterfaceID   uint32
	clientInterfaceType uint32
	serverInterfaceID   uint32
	serverInterfaceType uint32

	// family stores the family indicator of the session
	family uint32

	// conntrackConfirmed is true if this session has been confirmed by conntrack. false otherwise
	// A session becomes confirmed by conntrack once its packet reaches the final CONNTRACK_CONFIRM
	// priority in netfilter, and we get an conntrack "NEW" event for it.
	// Packets that never reach this point (blocked packets) often never get confirmed
	conntrackConfirmed uint32

	// The conntrack entry associated with this session
	conntrackPointer *Conntrack
	conntrackLock    sync.RWMutex

	// subscriptions stores the nfqueue subscribers
	subscriptions map[string]SubscriptionHolder
	subLocker     sync.RWMutex

	// attachments stores the metadata attachments
	attachments    map[string]interface{}
	attachmentLock sync.RWMutex

	// used to keep track of the last session activity
	lastActivityTime time.Time
	lastActivityLock sync.RWMutex
}

// sessionTable is the global session table
var sessionTable map[uint32]*Session

// sessionMutex is the lock for sessionTable
var sessionMutex sync.RWMutex

// sessionIndex stores the next available unique SessionID
var sessionIndex int64

// PutAttachment is used to safely add an attachment to a session object
func (sess *Session) PutAttachment(name string, value interface{}) {
	sess.attachmentLock.Lock()
	sess.attachments[name] = value
	sess.attachmentLock.Unlock()
}

// GetAttachment is used to safely get an attachment from a session object
func (sess *Session) GetAttachment(name string) interface{} {
	sess.attachmentLock.RLock()
	value := sess.attachments[name]
	sess.attachmentLock.RUnlock()
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

// GetSessionID gets the session ID
func (sess *Session) GetSessionID() int64 {
	return atomic.LoadInt64(&sess.sessionID)
}

// SetSessionID sets the seession ID
func (sess *Session) SetSessionID(value int64) int64 {
	atomic.StoreInt64(&sess.sessionID, value)
	return value
}

// GetConntrackID gets the conntrack ID
func (sess *Session) GetConntrackID() uint32 {
	return atomic.LoadUint32(&sess.conntrackID)
}

// SetConntrackID sets the conntrack ID
func (sess *Session) SetConntrackID(value uint32) uint32 {
	atomic.StoreUint32(&sess.conntrackID, value)
	return value
}

// GetClientSideTuple gets the client side Tuple
func (sess *Session) GetClientSideTuple() Tuple {
	sess.clientSideLock.RLock()
	value := sess.clientSideTuple
	sess.clientSideLock.RUnlock()
	return value
}

// SetClientSideTuple sets the client side Tuple
func (sess *Session) SetClientSideTuple(tuple Tuple) {
	sess.clientSideLock.Lock()
	sess.clientSideTuple = tuple
	sess.clientSideLock.Unlock()
}

// GetServerSideTuple gets the server side Tuple
func (sess *Session) GetServerSideTuple() Tuple {
	sess.serverSideLock.RLock()
	value := sess.serverSideTuple
	sess.serverSideLock.RUnlock()
	return value
}

// SetServerSideTuple sets the server side Tuple
func (sess *Session) SetServerSideTuple(tuple Tuple) {
	sess.serverSideLock.Lock()
	sess.serverSideTuple = tuple
	sess.serverSideLock.Unlock()
}

// GetServerInterfaceID gets the server interface ID
func (sess *Session) GetServerInterfaceID() uint8 {
	return uint8(atomic.LoadUint32(&sess.serverInterfaceID))
}

// SetServerInterfaceID sets the server interface ID
func (sess *Session) SetServerInterfaceID(value uint8) uint8 {
	atomic.StoreUint32(&sess.serverInterfaceID, uint32(value))
	return value
}

// GetServerInterfaceType gets the server interface type
func (sess *Session) GetServerInterfaceType() uint8 {
	return uint8(atomic.LoadUint32(&sess.serverInterfaceType))
}

// SetServerInterfaceType sets the server interface type
func (sess *Session) SetServerInterfaceType(value uint8) uint8 {
	atomic.StoreUint32(&sess.serverInterfaceType, uint32(value))
	return value
}

// GetClientInterfaceID gets the client interface ID
func (sess *Session) GetClientInterfaceID() uint8 {
	return uint8(atomic.LoadUint32(&sess.clientInterfaceID))
}

// SetClientInterfaceID sets the client interface ID
func (sess *Session) SetClientInterfaceID(value uint8) uint8 {
	atomic.StoreUint32(&sess.clientInterfaceID, uint32(value))
	return value
}

// GetClientInterfaceType gets the client interface type
func (sess *Session) GetClientInterfaceType() uint8 {
	return uint8(atomic.LoadUint32(&sess.clientInterfaceType))
}

// SetClientInterfaceType sets the client interface type
func (sess *Session) SetClientInterfaceType(value uint8) uint8 {
	atomic.StoreUint32(&sess.clientInterfaceType, uint32(value))
	return value
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

// GetNavlCount gets the navl count
func (sess *Session) GetNavlCount() uint64 {
	return atomic.LoadUint64(&sess.navlCount)
}

// SetNavlCount sets the navl count
func (sess *Session) SetNavlCount(value uint64) uint64 {
	atomic.StoreUint64(&sess.navlCount, value)
	return value
}

// AddNavlCount increases the navl count by the argumented value
func (sess *Session) AddNavlCount(value uint64) uint64 {
	return atomic.AddUint64(&sess.navlCount, value)
}

// GetCreationTime gets the time the entry was created
func (sess *Session) GetCreationTime() time.Time {
	sess.creationLock.RLock()
	value := sess.creationTime
	sess.creationLock.RUnlock()
	return value
}

// SetCreationTime sets the time the entry was created
func (sess *Session) SetCreationTime(value time.Time) {
	sess.creationLock.Lock()
	sess.creationTime = value
	sess.creationLock.Unlock()
}

// GetLastActivity gets the time of the last session activity
func (sess *Session) GetLastActivity() time.Time {
	sess.lastActivityLock.RLock()
	value := sess.lastActivityTime
	sess.lastActivityLock.RUnlock()
	return value
}

// SetLastActivity sets the time of the last session activity
func (sess *Session) SetLastActivity(value time.Time) {
	sess.lastActivityLock.Lock()
	sess.lastActivityTime = value
	sess.lastActivityLock.Unlock()
}

// GetConntrackConfirmed gets the conntrack confirmed flag
func (sess *Session) GetConntrackConfirmed() bool {
	if atomic.LoadUint32(&sess.conntrackConfirmed) == 0 {
		return false
	}
	return true
}

// SetConntrackConfirmed sets the conntrack confirmed flag
func (sess *Session) SetConntrackConfirmed(argument bool) {
	if argument {
		atomic.StoreUint32(&sess.conntrackConfirmed, 1)
	} else {
		atomic.StoreUint32(&sess.conntrackConfirmed, 0)
	}
}

// GetConntrackPointer gets the conntrack pointer
func (sess *Session) GetConntrackPointer() *Conntrack {
	sess.conntrackLock.RLock()
	value := sess.conntrackPointer
	sess.conntrackLock.RUnlock()
	return value
}

// SetConntrackPointer sets the conntrack pointer
func (sess *Session) SetConntrackPointer(pointer *Conntrack) {
	sess.conntrackLock.Lock()
	sess.conntrackPointer = pointer
	sess.conntrackLock.Unlock()
}

// GetFamily gets the session family type
func (sess *Session) GetFamily() uint8 {
	return uint8(atomic.LoadUint32(&sess.family))
}

// SetFamily sets the session family type
func (sess *Session) SetFamily(value uint8) uint8 {
	atomic.StoreUint32(&sess.family, uint32(value))
	return value
}

// removeFromSessionTable removes the session from the session table
// it does a sanity check to make sure the session in question
// is actually in the table
func (sess *Session) removeFromSessionTable() {
	sessionMutex.Lock()
	sessInTable, found := sessionTable[sess.GetConntrackID()]
	if found && sess == sessInTable {
		delete(sessionTable, sess.GetConntrackID())
	}
	sessionMutex.Unlock()
}

// flushDict flushes the dict for the session
// it does a sanity check to make sure it ows its ctid
// by doing a lookup in the session table
func (sess *Session) flushDict() {
	sessionMutex.Lock()
	sessInTable, found := sessionTable[sess.GetConntrackID()]
	if found && sess == sessInTable {
		dict.DeleteSession(sess.GetConntrackID())
	}
	sessionMutex.Unlock()
}

// nextSessionID returns the next sequential session ID value
func nextSessionID() int64 {
	var value int64
	sessionMutex.Lock()
	value = sessionIndex
	sessionIndex++

	if sessionIndex < 0 {
		sessionIndex = 1
	}

	sessionMutex.Unlock()
	return (value)
}

// findSession searches for an sess in the session table
func findSession(ctid uint32) *Session {
	sessionMutex.RLock()
	sess, status := sessionTable[ctid]
	logger.Trace("Lookup session index %v -> %v\n", ctid, status)
	sessionMutex.RUnlock()
	if status == false {
		return nil
	}
	return sess
}

// insertSessionTable adds an sess to the session table
func insertSessionTable(ctid uint32, sess *Session) {
	logger.Trace("Insert session index %v -> %v\n", ctid, sess.GetClientSideTuple())
	sessionMutex.Lock()
	if sessionTable[ctid] != nil {
		logger.Warn("Overriding previous session: %v\n", ctid)
		delete(sessionTable, ctid)
	}
	sessionTable[ctid] = sess
	sessionMutex.Unlock()
	dict.AddSessionEntry(sess.GetConntrackID(), "session_id", sess.GetSessionID())
}

// cleanSessionTable cleans the session table by removing stale entries
func cleanSessionTable() {
	sessionMutex.Lock()
	defer sessionMutex.Unlock()

	for ctid, session := range sessionTable {
		// Having stale sessions is normal if sessions get blocked. Their conntrack is
		// never get confirmed and thus there is never a delete conntrack event so we
		// clean those session up quickly to keep the dict from getting huge.
		// However, if we find a a stale conntrack-confirmed session that is bad.
		if session.GetConntrackConfirmed() {
			// We use 10000 seconds for confirmed sessions because 7440 is the established idle tcp timeout default
			if time.Now().Sub(session.GetLastActivity()) > 10000*time.Second {
				logger.Err("%OC|Removing stale (%v) session [%v] %v\n", "stale_session_removed", 0, time.Now().Sub(session.GetLastActivity()), ctid, session.GetClientSideTuple())
				dict.DeleteSession(ctid)
				delete(sessionTable, ctid)
			}
		} else {
			// We remove unconfirmed sessions after 60 seconds to keep things lean and clean
			if time.Now().Sub(session.GetLastActivity()) > 60*time.Second {
				if logger.IsTraceEnabled() {
					logger.Err("Removing unconfirmed (%v) session [%v] %v\n", time.Now().Sub(session.GetLastActivity()), ctid, session.GetClientSideTuple())
				}
				overseer.AddCounter("unconfirmed_session_removed", 1)
				dict.DeleteSession(ctid)
				delete(sessionTable, ctid)
			}
		}
	}
}

// printSessionTable prints the session table
func printSessionTable() {
	sessionMutex.RLock()
	defer sessionMutex.RUnlock()
	for k, v := range sessionTable {
		logger.Debug("Session[%v] = %s\n", k, v.GetClientSideTuple().String())
	}
}
