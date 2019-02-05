package dispatch

import (
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/untangle/packetd/services/logger"
)

// ConntrackHandlerFunction defines a pointer to a conntrack callback function
type ConntrackHandlerFunction func(int, *Conntrack)

// Conntrack stores the details of a conntrack entry
type Conntrack struct {
	ConntrackID      uint32
	ConnMark         uint32
	Session          *Session
	SessionID        uint64
	CreationTime     time.Time
	LastActivityTime time.Time
	LastUpdateTime   time.Time
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

var conntrackTable map[uint32]*Conntrack
var conntrackTableMutex sync.Mutex

// String returns string representation of conntrack
func (c Conntrack) String() string {
	return strconv.Itoa(int(c.ConntrackID)) + "|" + c.ClientSideTuple.String()
}

// removeConntrack remove an entry from the conntrackTable that is obsolete/dead/invalid
func removeConntrack2(ctid uint32, conntrack *Conntrack) {
	removeConntrack(ctid)

	// We only want to remove the specific session
	// There is a race, we may get this DELETE event after the ctid has been reused by a new session
	// and we don't want to remove that mapping from the session table
	if conntrack != nil && conntrack.Session != nil {
		conntrack.Session.destroy()
	}
}

// conntrackCallback is the global conntrack event handler
func conntrackCallback(ctid uint32, connmark uint32, family uint8, eventType uint8, protocol uint8,
	client net.IP, server net.IP, clientPort uint16, serverPort uint16,
	clientNew net.IP, serverNew net.IP, clientPortNew uint16, serverPortNew uint16,
	c2sBytes uint64, s2cBytes uint64) {

	var conntrack *Conntrack
	var conntrackFound bool

	// start by looking for the existing conntrack entry
	conntrack, conntrackFound = findConntrack(ctid)

	if logger.IsTraceEnabled() {
		logger.Trace("conntrack event[%c]: %v %v:%v->%v:%v\n", eventType, ctid, client, clientPort, server, serverPort)
	}

	// sanity check tuple for all eventType
	if conntrackFound && conntrack != nil {
		var clientSideTuple Tuple
		clientSideTuple.Protocol = protocol
		clientSideTuple.ClientAddress = dupIP(client)
		clientSideTuple.ClientPort = clientPort
		clientSideTuple.ServerAddress = dupIP(server)
		clientSideTuple.ServerPort = serverPort
		if eventType == 'N' {
			// if this is a new conntrack event, we should not have found a conntrack with that ctid
			logger.Err("Received conntract NEW event for existing ctid %d\n", ctid)
			logger.Err("New:\n")
			logger.Err("ClientSideTuple: %v\n", clientSideTuple)
			logger.Err("Old:\n")
			logger.Err("ClientSideTuple: %v\n", conntrack.ClientSideTuple)
			logger.Err("ServerSideTuple: %v\n", conntrack.ServerSideTuple)
			logger.Err("CreationTime: %v ago\n", time.Now().Sub(conntrack.CreationTime))
			logger.Err("LastActivityTime: %v ago\n", time.Now().Sub(conntrack.LastActivityTime))
			logger.Err("ConntrackID: %v\n", conntrack.ConntrackID)
			logger.Err("SessionID: %v\n", conntrack.SessionID)
			if conntrack.Session != nil {
				logger.Err("Session ClientSideTuple: %v\n", conntrack.Session.ClientSideTuple)
				logger.Err("Session ServerSideTuple: %v\n", conntrack.Session.ServerSideTuple)
				logger.Err("Session SessionID: %v\n", conntrack.Session.SessionID)
			}
			logger.Err("Deleting obsolete conntrack entry %v.\n", ctid)
			removeConntrack2(ctid, conntrack)
			conntrackFound = false
			conntrack = nil
		} else if !clientSideTuple.Equal(conntrack.ClientSideTuple) {
			// if the tuple isn't what we expect something has gone wrong
			logger.Warn("Conntrack event[%c] tuple mismatch %v\n", eventType, ctid)
			logger.Warn("Actual: %s Expected: %s\n", clientSideTuple.String(), conntrack.ClientSideTuple.String())
			logger.Err("Deleting obsolete conntrack entry %v.\n", ctid)
			removeConntrack2(ctid, conntrack)
			conntrackFound = false
			conntrack = nil
		}
	}

	// handle DELETE events
	if eventType == 'D' {
		// do not call subscribers for ID's we don't know about
		if conntrackFound == false {
			logger.Debug("Received conntrack delete for unknown id %d\n", ctid)
			return
		}

		removeConntrack2(ctid, conntrack)
	}

	// handle NEW events
	if eventType == 'N' {
		conntrack = createConntrack(ctid, connmark, family, eventType, protocol,
			client, server, clientPort, serverPort,
			clientNew, serverNew, clientPortNew, serverPortNew,
			c2sBytes, s2cBytes)

		// look for the session entry
		session := findSession(ctid)

		// Do some sanity checks on the session we just found
		if session != nil {
			if session.ConntrackID != ctid {
				// We found a session, if its conntrackID does not match the one of the event
				// This should never happen as we lookup the session using the ctid
				logger.Err("Conntrack NEW ID mismatch: %s  %d != %d\n", session.ClientSideTuple.String(), ctid, session.ConntrackID)
				return
			}
			if !session.ClientSideTuple.Equal(conntrack.ClientSideTuple) {
				// We found a session, but the tuple is not what we expect.

				// This happens in some scenarios. For example:
				// A packet comes in and gets merged with another conntrack ID or dropped
				// in this case the ctid is in the session table from the nfqueue handler, but it has not been conntrack confirmed yet.
				// This server creates a new outbound connection (we don't queue our own packets outbound)
				// In this case we'll get a conntrack NEW event for the outbound connection, but not an nfqueue event.
				// This NEW event will have the correct tuple, but it won't match the previous session.
				// This is normal.

				// This is a problem, however if the previous session was confirmed, and we have now received a NEW event
				// before receiving a DELETE event for the old ctid
				if session.ConntrackConfirmed {
					logger.Err("Conntrack NEW session tuple mismatch: %v  %v != %v\n", ctid, session.ClientSideTuple.String(), conntrack.ClientSideTuple.String())
				} else {
					logger.Debug("Conntrack NEW session tuple mismatch: %v  %v != %v\n", ctid, session.ClientSideTuple.String(), conntrack.ClientSideTuple.String())
				}

				// Remove that session from the sessionTable - we can conclude its not valid anymore
				session.destroy()
				session = nil
			}
		}

		// if we find the session entry update with the server side tuple and
		// create another index for the session using the server side tuple
		if session != nil {
			session.ServerSideTuple.Protocol = protocol
			session.ServerSideTuple.ClientAddress = dupIP(clientNew)
			session.ServerSideTuple.ClientPort = clientPortNew
			session.ServerSideTuple.ServerAddress = dupIP(serverNew)
			session.ServerSideTuple.ServerPort = serverPortNew
			session.ServerInterfaceID = uint8((conntrack.ConnMark & 0x0000FF00) >> 8)
			session.ServerInterfaceType = uint8((conntrack.ConnMark & 0x0C000000) >> 26)
			session.ConntrackConfirmed = true
			session.Conntrack = conntrack
			session.LastActivityTime = time.Now()
			session.AddEventCount(1)
			conntrack.Session = session
			conntrack.SessionID = session.SessionID
		} else {
			conntrack.SessionID = nextSessionID()
		}

		insertConntrack(ctid, conntrack)
	}

	// handle UPDATE events
	if eventType == 'U' {

		// We did not find an existing conntarck entry for this update event
		// This means we likely missed the new event when we create & insert the conntrack entry
		// Create one now
		if conntrackFound == false {
			conntrack = createConntrack(ctid, connmark, family, eventType, protocol,
				client, server, clientPort, serverPort,
				clientNew, serverNew, clientPortNew, serverPortNew,
				c2sBytes, s2cBytes)
			insertConntrack(ctid, conntrack)
		}

		previousUpdateTime := conntrack.LastUpdateTime
		conntrack.LastActivityTime = time.Now()
		conntrack.LastUpdateTime = conntrack.LastActivityTime
		var secondsSinceLastUpdate float32
		if previousUpdateTime.IsZero() {
			secondsSinceLastUpdate = float32(conntrackIntervalSeconds)
		} else {
			secondsSinceLastUpdate = float32(conntrack.LastUpdateTime.Sub(previousUpdateTime).Seconds())
		}

		conntrack.EventCount++
		if (connmark & 0x0fffffff) != (conntrack.ConnMark & 0x0fffffff) {
			logger.Info("Connmark change [%v] 0x%08x != 0x%08x\n", conntrack.ClientSideTuple, connmark, conntrack.ConnMark)
			conntrack.ConnMark = connmark
		}
		if conntrack.Session != nil {
			conntrack.Session.LastActivityTime = time.Now()
			conntrack.Session.AddEventCount(1)
		}

		oldC2sBytes := conntrack.C2SBytes
		oldS2cBytes := conntrack.S2CBytes
		oldTotalBytes := conntrack.TotalBytes
		newC2sBytes := c2sBytes
		newS2cBytes := s2cBytes
		newTotalBytes := (newC2sBytes + newS2cBytes)
		diffC2sBytes := (newC2sBytes - oldC2sBytes)
		diffS2cBytes := (newS2cBytes - oldS2cBytes)
		diffTotalBytes := (newTotalBytes - oldTotalBytes)

		// In some cases, specifically UDP, a new session takes the place of an old session with the same tuple.
		// In this case the counts go down because its actually a new session. If the total Bytes is low, this
		// is probably the case so treat it as a new conntrack.
		if (diffC2sBytes < 0) || (diffS2cBytes < 0) {
			newC2sBytes = c2sBytes
			diffC2sBytes = newC2sBytes
			newS2cBytes = s2cBytes
			diffS2cBytes = newS2cBytes
			newTotalBytes = (newC2sBytes + newS2cBytes)
			diffTotalBytes = newTotalBytes
		}

		c2sRate := float32(diffC2sBytes) / secondsSinceLastUpdate
		s2cRate := float32(diffS2cBytes) / secondsSinceLastUpdate
		totalRate := float32(diffTotalBytes) / secondsSinceLastUpdate

		conntrack.C2SBytes = newC2sBytes
		conntrack.S2CBytes = newS2cBytes
		conntrack.TotalBytes = newTotalBytes
		conntrack.C2SBytesDiff = diffC2sBytes
		conntrack.S2CBytesDiff = diffS2cBytes
		conntrack.TotalBytesDiff = diffTotalBytes
		conntrack.C2SRate = c2sRate
		conntrack.S2CRate = s2cRate
		conntrack.TotalRate = totalRate
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
				val.ConntrackFunc(int(eventType), conntrack)
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

// findConntrack finds an entry in the conntrack table
func findConntrack(ctid uint32) (*Conntrack, bool) {
	conntrackTableMutex.Lock()
	defer conntrackTableMutex.Unlock()
	entry, status := conntrackTable[ctid]
	return entry, status
}

// insertConntrack adds an entry to the conntrack table
func insertConntrack(ctid uint32, entry *Conntrack) {
	logger.Trace("Insert conntrack entry %d\n", ctid)
	conntrackTableMutex.Lock()
	defer conntrackTableMutex.Unlock()
	if conntrackTable[ctid] != nil {
		delete(conntrackTable, ctid)
	}
	conntrackTable[ctid] = entry
}

// removeConntrack removes an entry from the conntrack table
func removeConntrack(ctid uint32) {
	logger.Trace("Remove conntrack entry %d\n", ctid)
	conntrackTableMutex.Lock()
	defer conntrackTableMutex.Unlock()
	delete(conntrackTable, ctid)
}

// cleanConntrackTable cleans the conntrack table by removing stale entries
func cleanConntrackTable() {
	conntrackTableMutex.Lock()
	defer conntrackTableMutex.Unlock()

	for ctid, conntrack := range conntrackTable {
		// We use 10000 seconds because 7440 is the established idle tcp timeout default
		if time.Now().Sub(conntrack.LastActivityTime) > 10000*time.Second {
			// This should never happen, log an error
			// entries should be removed by DELETE events
			// otherwise they should be getting UPDATE events and the LastActivityTime
			// would be at least within interval seconds.
			// The the entry exists, the LastActivityTime is a long time ago
			// some constraint has failed
			logger.Err("Removing stale (%v) conntrack entry [%d] %v\n", time.Now().Sub(conntrack.LastActivityTime), ctid, conntrack.ClientSideTuple)
			delete(conntrackTable, ctid)
		}
	}
}

// createConntrack creates a new conntrack entry
func createConntrack(ctid uint32, connmark uint32, family uint8, eventType uint8, protocol uint8,
	client net.IP, server net.IP, clientPort uint16, serverPort uint16,
	clientNew net.IP, serverNew net.IP, clientPortNew uint16, serverPortNew uint16,
	c2sBytes uint64, s2cBytes uint64) *Conntrack {
	conntrack := new(Conntrack)
	conntrack.ConntrackID = ctid
	conntrack.ConnMark = connmark
	conntrack.CreationTime = time.Now()
	conntrack.LastActivityTime = time.Now()
	conntrack.EventCount = 1
	conntrack.ClientSideTuple.Protocol = protocol
	conntrack.ClientSideTuple.ClientAddress = dupIP(client)
	conntrack.ClientSideTuple.ClientPort = clientPort
	conntrack.ClientSideTuple.ServerAddress = dupIP(server)
	conntrack.ClientSideTuple.ServerPort = serverPort
	conntrack.ServerSideTuple.Protocol = protocol
	conntrack.ServerSideTuple.ClientAddress = dupIP(clientNew)
	conntrack.ServerSideTuple.ClientPort = clientPortNew
	conntrack.ServerSideTuple.ServerAddress = dupIP(serverNew)
	conntrack.ServerSideTuple.ServerPort = serverPortNew
	return conntrack
}
