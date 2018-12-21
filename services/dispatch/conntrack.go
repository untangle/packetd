package dispatch

import (
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/untangle/packetd/services/logger"
)

// ConntrackHandlerFunction defines a pointer to a conntrack callback function
type ConntrackHandlerFunction func(int, *ConntrackEntry)

// ConntrackEntry stores the details of a conntrack entry
type ConntrackEntry struct {
	ConntrackID      uint32
	ConnMark         uint32
	Session          *SessionEntry
	SessionID        uint64
	CreationTime     time.Time
	LastActivityTime time.Time
	ClientSideTuple  Tuple
	ServerSideTuple  Tuple
	EventCount       uint64
	C2SBytes         uint64
	S2CBytes         uint64
	TotalBytes       uint64
	C2SBytesDiff     uint64  // the C2SBytes diff since last update
	S2CBytesDiff     uint64  // the S2CBytes diff since last update
	TotalBytesDiff   uint64  // the TotalBytes diff since last update
	C2SRate          float32 // the c2s byte rate site the last update
	S2CRate          float32 // the s2c byte rate site the last update
	TotalRate        float32 // the total byte rate site the last update
}

var conntrackTable map[uint32]*ConntrackEntry
var conntrackTableMutex sync.Mutex

// String returns string representation of conntrack
func (c ConntrackEntry) String() string {
	return strconv.Itoa(int(c.ConntrackID)) + "|" + c.ClientSideTuple.String()
}

// conntrackCallback is the global conntrack event handler
func conntrackCallback(ctid uint32, connmark uint32, family uint8, eventType uint8, protocol uint8,
	client net.IP, server net.IP, clientPort uint16, serverPort uint16,
	clientNew net.IP, serverNew net.IP, clientPortNew uint16, serverPortNew uint16,
	c2sBytes uint64, s2cBytes uint64) {

	var conntrackEntry *ConntrackEntry
	var conntrackFound bool

	// start by looking for the existing conntrack entry
	conntrackEntry, conntrackFound = findConntrackEntry(ctid)

	logger.Trace("conntrack event[%c]: %v 0x%08x\n", eventType, ctid, connmark)

	// handle DELETE events
	if eventType == 'D' {
		// do not call subscribers for ID's we don't know about
		if conntrackFound == false {
			logger.Debug("Received conntrack delete for unknown id %d\n", ctid)
			return
		}

		var clientSideTuple Tuple
		clientSideTuple.Protocol = protocol
		clientSideTuple.ClientAddress = dupIP(client)
		clientSideTuple.ClientPort = clientPort
		clientSideTuple.ServerAddress = dupIP(server)
		clientSideTuple.ServerPort = serverPort

		if !clientSideTuple.Equal(conntrackEntry.ClientSideTuple) {
			// We found a session, but the tuple is not what we expect.
			// something has gone wrong
			logger.Err("Conntrack DELETE tuple mismatch: %v  %s != %s\n", ctid, clientSideTuple.String(), conntrackEntry.ClientSideTuple.String())
			return
		}
		removeConntrackEntry(ctid)

		// look for the session entry
		session := findSessionEntry(ctid)
		if session != conntrackEntry.Session {
			logger.Err("Conntrack DELETE session mismatch: %v  %v != %s\n", ctid, session, conntrackEntry.Session)
			return
		}

		if session != nil {
			if !clientSideTuple.Equal(session.ClientSideTuple) {
				logger.Err("Conntrack DELETE session tuple mismatch: %v  %s != %s\n", ctid, clientSideTuple.String(), session.ClientSideTuple.String())
				return
			}
			removeSessionEntry(ctid)
		}
	}

	// handle NEW events
	if eventType == 'N' {

		origConntrackEntry := conntrackEntry
		conntrackEntry = new(ConntrackEntry)
		conntrackEntry.ConntrackID = ctid
		conntrackEntry.ConnMark = connmark
		conntrackEntry.CreationTime = time.Now()
		conntrackEntry.LastActivityTime = time.Now()
		conntrackEntry.EventCount = 1
		conntrackEntry.ClientSideTuple.Protocol = protocol
		conntrackEntry.ClientSideTuple.ClientAddress = dupIP(client)
		conntrackEntry.ClientSideTuple.ClientPort = clientPort
		conntrackEntry.ClientSideTuple.ServerAddress = dupIP(server)
		conntrackEntry.ClientSideTuple.ServerPort = serverPort
		conntrackEntry.ServerSideTuple.Protocol = protocol
		conntrackEntry.ServerSideTuple.ClientAddress = dupIP(clientNew)
		conntrackEntry.ServerSideTuple.ClientPort = clientPortNew
		conntrackEntry.ServerSideTuple.ServerAddress = dupIP(serverNew)
		conntrackEntry.ServerSideTuple.ServerPort = serverPortNew

		// look for the session entry
		session := findSessionEntry(ctid)

		// if this is a NEW event, and we already had a conntrackEntry for this ctid
		// something has gone wrong
		if conntrackFound == true {
			logger.Err("Received conntract NEW event for existing ctid %d\n", ctid)
			logger.Err("Old vs New %v %v\n", origConntrackEntry.ClientSideTuple, conntrackEntry.ClientSideTuple)
			logger.Err("Old conntrackEntry:\n")
			logger.Err("Creation Time: %v ago\n", time.Now().Sub(origConntrackEntry.CreationTime))
			logger.Err("Last Activity Time: %v ago\n", time.Now().Sub(origConntrackEntry.LastActivityTime))
			logger.Err("Conntrack ID: %v\n", origConntrackEntry.SessionID)
			if session != nil {
				logger.Err("Session Tuple: %v %v\n", session.ClientSideTuple, session.ServerSideTuple)
				logger.Err("Session ID: %v\n", session.SessionID)
			}
			return
		}

		// if we find the session entry update with the server side tuple and
		// create another index for the session using the server side tuple
		if session != nil {
			if session.ConntrackID != ctid {
				// We found a session, if its conntrackID does not match the one of the event
				// something has gone wrong
				logger.Err("Conntrack NEW ID mismatch: %s  %d != %d\n", session.ClientSideTuple.String(), ctid, session.ConntrackID)
				return
			}
			if session.ConntrackConfirmed {
				// if the session we found is already conntrack confirmed
				// something has gone wrong
				logger.Err("Conntrack NEW for confirmed session: %v %v %v\n", ctid, session.ClientSideTuple.String(), conntrackEntry.ClientSideTuple.String())
				return
			}
			if !session.ClientSideTuple.Equal(conntrackEntry.ClientSideTuple) {
				// We found a session, but the tuple is not what we expect.
				// something has gone wrong
				logger.Err("Conntrack NEW tuple mismatch: %v  %v != %v\n", ctid, session.ClientSideTuple.String(), conntrackEntry.ClientSideTuple.String())
				return
			}

			session.ServerSideTuple.Protocol = protocol
			session.ServerSideTuple.ClientAddress = dupIP(clientNew)
			session.ServerSideTuple.ClientPort = clientPortNew
			session.ServerSideTuple.ServerAddress = dupIP(serverNew)
			session.ServerSideTuple.ServerPort = serverPortNew
			session.ConntrackConfirmed = true
			session.ConntrackEntry = conntrackEntry
			session.LastActivityTime = time.Now()
			session.EventCount++
			conntrackEntry.Session = session
			conntrackEntry.SessionID = session.SessionID
		} else {
			conntrackEntry.SessionID = nextSessionID()
		}

		insertConntrackEntry(ctid, conntrackEntry)
	}

	// handle UPDATE events
	if eventType == 'U' {

		// do not call subscribers for ID's we don't know about
		if conntrackFound == false {
			logger.Debug("Received conntract update for unknown id %d\n", ctid)
			return
		}

		conntrackEntry.LastActivityTime = time.Now()
		conntrackEntry.EventCount++
		if (connmark & 0x0fffffff) != (conntrackEntry.ConnMark & 0x0fffffff) {
			logger.Info("Connmark change [%v] 0x%08x != 0x%08x\n", conntrackEntry.ClientSideTuple, connmark, conntrackEntry.ConnMark)
			conntrackEntry.ConnMark = connmark
		}
		if conntrackEntry.Session != nil {
			conntrackEntry.Session.LastActivityTime = time.Now()
			conntrackEntry.Session.EventCount++
		}

		oldC2sBytes := conntrackEntry.C2SBytes
		oldS2cBytes := conntrackEntry.S2CBytes
		oldTotalBytes := conntrackEntry.TotalBytes
		newC2sBytes := c2sBytes
		newS2cBytes := s2cBytes
		newTotalBytes := (newC2sBytes + newS2cBytes)
		diffC2sBytes := (newC2sBytes - oldC2sBytes)
		diffS2cBytes := (newS2cBytes - oldS2cBytes)
		diffTotalBytes := (newTotalBytes - oldTotalBytes)

		// In some cases, specifically UDP, a new session takes the place of an old session with the same tuple.
		// In this case the counts go down because its actually a new session. If the total Bytes is low, this
		// is probably the case so treat it as a new conntrackEntry.
		if (diffC2sBytes < 0) || (diffS2cBytes < 0) {
			newC2sBytes = c2sBytes
			diffC2sBytes = newC2sBytes
			newS2cBytes = s2cBytes
			diffS2cBytes = newS2cBytes
			newTotalBytes = (newC2sBytes + newS2cBytes)
			diffTotalBytes = newTotalBytes
		}

		c2sRate := float32(diffC2sBytes / 60)
		s2cRate := float32(diffS2cBytes / 60)
		totalRate := float32(diffTotalBytes / 60)

		conntrackEntry.C2SBytes = newC2sBytes
		conntrackEntry.S2CBytes = newS2cBytes
		conntrackEntry.TotalBytes = newTotalBytes
		conntrackEntry.C2SBytesDiff = diffC2sBytes
		conntrackEntry.S2CBytesDiff = diffS2cBytes
		conntrackEntry.TotalBytesDiff = diffTotalBytes
		conntrackEntry.C2SRate = c2sRate
		conntrackEntry.S2CRate = s2cRate
		conntrackEntry.TotalRate = totalRate
	}

	// We loop and increment the priority until all subscriptions have been called
	sublist := conntrackSubList
	subtotal := len(sublist)
	subcount := 0
	priority := 0

	for subcount != subtotal {
		var wg sync.WaitGroup

		// Call all of the subscribed handlers for the current priority
		for key, val := range sublist {
			if val.Priority != priority {
				continue
			}
			logger.Debug("Calling conntrack APP:%s PRIORITY:%d\n", key, priority)
			wg.Add(1)
			go func(val SubscriptionHolder) {
				val.ConntrackFunc(int(eventType), conntrackEntry)
				wg.Done()
				logger.Debug("Finished conntrack APP:%s PRIORITY:%d\n", val.Owner, val.Priority)
			}(val)
			subcount++
		}

		// Wait on all of this priority to finish
		wg.Wait()

		// Increment the priority and keep looping until we've called all subscribers
		priority++
	}
}

// findConntrackEntry finds an entry in the conntrack table
func findConntrackEntry(finder uint32) (*ConntrackEntry, bool) {
	conntrackTableMutex.Lock()
	defer conntrackTableMutex.Unlock()
	entry, status := conntrackTable[finder]
	return entry, status
}

// insertConntrackEntry adds an entry to the conntrack table
func insertConntrackEntry(finder uint32, entry *ConntrackEntry) {
	logger.Trace("Insert conntrack entry %d\n", finder)
	conntrackTableMutex.Lock()
	defer conntrackTableMutex.Unlock()
	if conntrackTable[finder] != nil {
		delete(conntrackTable, finder)
	}
	conntrackTable[finder] = entry
}

// removeConntrackEntry removes an entry from the conntrack table
func removeConntrackEntry(finder uint32) {
	logger.Trace("Remove conntrack entry %d\n", finder)
	conntrackTableMutex.Lock()
	defer conntrackTableMutex.Unlock()
	delete(conntrackTable, finder)
}

// cleanConntrackTable cleans the conntrack table by removing stale entries
func cleanConntrackTable() {
	nowtime := time.Now()
	for key, val := range conntrackTable {
		if (nowtime.Unix() - val.LastActivityTime.Unix()) < 1800 {
			continue
		}
		// This should never happen, log an error
		// entries should be removed by DELETE events
		// otherwise they should be getting UPDATE events and the LastActivityTime
		// would be at least within 60 seconds.
		// The the entry exists, the LastActivityTime is a long time ago
		// some constraint has failed
		logger.Err("Removing stale conntrack entry %d: %v\n", key, val)
		removeConntrackEntry(key)
	}
}
