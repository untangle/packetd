package dispatch

import (
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/untangle/packetd/services/dict"
	"github.com/untangle/packetd/services/logger"
)

// ConntrackHandlerFunction defines a pointer to a conntrack callback function
type ConntrackHandlerFunction func(int, *Conntrack)

// Conntrack stores the details of a conntrack entry
type Conntrack struct {
	ConntrackID       uint32
	ConnMark          uint32
	Session           *Session
	SessionID         int64
	Family            uint8
	CreationTime      time.Time
	LastUpdateTime    time.Time
	LastActivityTime  time.Time
	ClientSideTuple   Tuple
	ServerSideTuple   Tuple
	TimeoutSeconds    uint32
	TimestampStart    uint64
	TimestampStop     uint64
	TCPState          uint8
	EventCount        uint64
	ClientBytes       uint64
	ServerBytes       uint64
	TotalBytes        uint64
	ClientPackets     uint64
	ServerPackets     uint64
	TotalPackets      uint64
	ClientBytesDiff   uint64  // the ClientBytes diff since last update
	ServerBytesDiff   uint64  // the ServerBytes diff since last update
	TotalBytesDiff    uint64  // the TotalBytes diff since last update
	ClientPacketsDiff uint64  // the ClientPackets diff since last update
	ServerPacketsDiff uint64  // the ServerPackets diff since last update
	TotalPacketsDiff  uint64  // the TotalPackets diff since last update
	ClientByteRate    float32 // the Client byte rate site the last update
	ServerByteRate    float32 // the Server byte rate site the last update
	TotalByteRate     float32 // the Total byte rate site the last update
	ClientPacketRate  float32 // the Client packet rate site the last update
	ServerPacketRate  float32 // the Server packet rate site the last update
	TotalPacketRate   float32 // the Total packet rate site the last update
	Guardian          sync.RWMutex
}

var conntrackTable map[uint32]*Conntrack
var conntrackTableMutex sync.RWMutex

// String returns string representation of conntrack
func (ct *Conntrack) String() string {
	return strconv.Itoa(int(ct.ConntrackID)) + "|" + ct.ClientSideTuple.String()
}

// conntrackCallback is the global conntrack event handler
func conntrackCallback(ctid uint32, connmark uint32, family uint8, eventType uint8, protocol uint8,
	client net.IP, server net.IP, clientPort uint16, serverPort uint16,
	clientNew net.IP, serverNew net.IP, clientPortNew uint16, serverPortNew uint16,
	clientBytes uint64, serverBytes uint64, clientPackets uint64, serverPackets uint64,
	timestampStart uint64, timestampStop uint64, timeout uint32, tcpState uint8) {

	if logger.IsTraceEnabled() {
		logger.Trace("conntrack event[%c]: %v %v:%v->%v:%v\n", eventType, ctid, client, clientPort, server, serverPort)
	}

	// We don't care about any loopback traffic
	if client.IsLoopback() || server.IsLoopback() {
		return
	}

	var conntrack *Conntrack
	var conntrackFound bool

	// start by looking for the existing conntrack entry
	conntrack, conntrackFound = findConntrack(ctid)

	// sanity check tuple for all eventType
	if conntrackFound && conntrack != nil {
		var clientSideTuple Tuple
		clientSideTuple.Protocol = protocol
		clientSideTuple.ClientAddress = dupIP(client)
		clientSideTuple.ClientPort = clientPort
		clientSideTuple.ServerAddress = dupIP(server)
		clientSideTuple.ServerPort = serverPort
		if eventType == 'N' {
			conntrack.Guardian.RLock()
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
				logger.Err("Session ClientSideTuple: %v\n", conntrack.Session.GetClientSideTuple())
				logger.Err("Session ServerSideTuple: %v\n", conntrack.Session.GetServerSideTuple())
				logger.Err("Session SessionID: %v\n", conntrack.Session.GetSessionID())
			}
			logger.Err("%OC|Deleting obsolete conntrack entry %v.\n", "contrack_obsolete_duplicate", 0, ctid)
			conntrack.Guardian.RUnlock()
			removeConntrackStale(ctid, conntrack)
			conntrackFound = false
			conntrack = nil
		} else if !clientSideTuple.Equal(conntrack.ClientSideTuple) {
			// if the tuple isn't what we expect something has gone wrong
			conntrack.Guardian.RLock()
			logger.Warn("Conntrack event[%c] tuple mismatch %v\n", eventType, ctid)
			logger.Warn("Actual: %s Expected: %s\n", clientSideTuple.String(), conntrack.ClientSideTuple.String())
			logger.Err("%OC|Deleting obsolete conntrack entry %v.\n", "contrack_obsolete_mismatch", 0, ctid)
			conntrack.Guardian.RUnlock()
			removeConntrackStale(ctid, conntrack)
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

		removeConntrackStale(ctid, conntrack)

		// just return now, we don't pass DELETE events to subscribers
		// DELETE events are not reliable (they can be missed)
		// As such, for now, we don't pass them to subscribers so that plugins
		// will not rely on DELETE events for cleanup
		return
	} // end of handle DELETE events

	// handle NEW events
	if eventType == 'N' {
		conntrack = createConntrack(ctid, connmark, family, eventType, protocol,
			client, server, clientPort, serverPort,
			clientNew, serverNew, clientPortNew, serverPortNew,
			clientBytes, serverBytes, clientPackets, serverPackets,
			timestampStart, timestampStop, timeout, tcpState)

		// look for the session entry
		session := findSession(ctid)

		// Do some sanity checks on the session we just found
		if session != nil {
			if session.GetConntrackID() != ctid {
				// We found a session, if its conntrackID does not match the one of the event
				// This should never happen as we lookup the session using the ctid
				logger.Err("%OC|Conntrack NEW ID mismatch: %s  %d != %d\n", "conntrack_new_id_mismatch", 0, session.GetClientSideTuple().String(), ctid, session.GetConntrackID())
				return
			}
			if !session.GetClientSideTuple().Equal(conntrack.ClientSideTuple) {
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
				if session.GetConntrackConfirmed() {
					logger.Err("%OC|Conntrack NEW session tuple mismatch: %v  %v != %v\n", "conntrack_new_session_mismatch", 0, ctid, session.GetClientSideTuple().String(), conntrack.ClientSideTuple.String())
				} else {
					logger.Debug("Conntrack NEW session tuple mismatch: %v  %v != %v\n", ctid, session.GetClientSideTuple().String(), conntrack.ClientSideTuple.String())
				}

				// Remove that session from the sessionTable - we can conclude its not valid anymore
				session.flushDict()
				session.removeFromSessionTable()
				session = nil
			}
		}

		// if we find the session entry update with the server side tuple and
		// create another index for the session using the server side tuple
		if session != nil {
			var serverSideTuple Tuple

			serverSideTuple.Protocol = protocol
			serverSideTuple.ClientAddress = dupIP(clientNew)
			serverSideTuple.ClientPort = clientPortNew
			serverSideTuple.ServerAddress = dupIP(serverNew)
			serverSideTuple.ServerPort = serverPortNew
			session.SetServerSideTuple(serverSideTuple)
			session.SetServerInterfaceID(uint8((conntrack.ConnMark & 0x0000FF00) >> 8))
			session.SetServerInterfaceType(uint8((conntrack.ConnMark & 0x0C000000) >> 26))
			session.SetConntrackConfirmed(true)
			session.SetConntrackPointer(conntrack)
			session.SetLastActivity(time.Now())
			session.AddEventCount(1)
			conntrack.Session = session
			conntrack.SessionID = session.GetSessionID()
		} else {
			conntrack.SessionID = nextSessionID()
		}

		insertConntrack(ctid, conntrack)
	} // end of handle NEW events

	// handle UPDATE events
	if eventType == 'U' {

		// We did not find an existing conntrack entry for this update event
		// This means we likely missed the new event when we create & insert the conntrack entry
		// Create one now
		if conntrackFound == false {
			conntrack = createConntrack(ctid, connmark, family, eventType, protocol,
				client, server, clientPort, serverPort,
				clientNew, serverNew, clientPortNew, serverPortNew,
				clientBytes, serverBytes, clientPackets, serverPackets,
				timestampStart, timestampStop, timeout, tcpState)
			insertConntrack(ctid, conntrack)
		}

		conntrack.Guardian.Lock()
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
			logger.Debug("Connmark change [%v] 0x%08x != 0x%08x\n", conntrack.ClientSideTuple, connmark, conntrack.ConnMark)
			conntrack.ConnMark = connmark
		}
		if conntrack.Session != nil {
			conntrack.Session.SetLastActivity(time.Now())
			conntrack.Session.AddEventCount(1)
		}

		conntrack.TimeoutSeconds = timeout
		conntrack.TCPState = tcpState
		conntrack.TimestampStart = timestampStart
		conntrack.TimestampStop = timestampStop

		updateStatsAndRates(conntrack, clientBytes, serverBytes, clientPackets, serverPackets, secondsSinceLastUpdate)
		conntrack.Guardian.Unlock()
	}

	// We loop and increment the priority until all subscriptions have been called
	sublist := conntrackSubList
	subtotal := len(sublist)
	subcount := 0
	priority := 0

	for subcount != subtotal {
		timeoutTimer := time.NewTimer(maxSubscriberTime)
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

		// Wait for all of this priority to finish. Calling the wait on a goroutine that closes a
		// channel allows us to wait for either the channel to close or the subscriber timeout
		c := make(chan bool)
		go func() {
			defer close(c)
			wg.Wait()
		}()
		select {
		case <-timeoutTimer.C:
			logger.Crit("%OC|Timeout while waiting for conntrack subcriber:%s\n", "timeout_conntrack", 0)
		case <-c:
			timeoutTimer.Stop()
		}

		// Increment the priority and keep looping until we've called all subscribers
		priority++
		if priority > 100 {
			logger.Err("%OC:Priority > 100 Constraint failed! %d %d %d %v", "conntrack_priority_constraint", 0, subcount, subtotal, priority, sublist)
			panic("Constraint failed - infinite loop detected")
		}
	}
}

// findConntrack finds an entry in the conntrack table
func findConntrack(ctid uint32) (*Conntrack, bool) {
	conntrackTableMutex.RLock()
	entry, status := conntrackTable[ctid]
	conntrackTableMutex.RUnlock()
	return entry, status
}

// insertConntrack adds an entry to the conntrack table
func insertConntrack(ctid uint32, entry *Conntrack) {
	logger.Trace("Insert conntrack entry %d\n", ctid)
	conntrackTableMutex.Lock()
	if conntrackTable[ctid] != nil {
		delete(conntrackTable, ctid)
	}
	conntrackTable[ctid] = entry
	conntrackTableMutex.Unlock()
}

// removeConntrack removes an entry from the conntrack table
func removeConntrack(ctid uint32) {
	logger.Trace("Remove conntrack entry %d\n", ctid)
	conntrackTableMutex.Lock()
	delete(conntrackTable, ctid)
	conntrackTableMutex.Unlock()
}

// removeConntrackStale remove an entry from the conntrackTable that is obsolete/dead/invalid
func removeConntrackStale(ctid uint32, conntrack *Conntrack) {
	removeConntrack(ctid)
	dict.DeleteSession(ctid)

	// We only want to remove the specific session
	// There is a race, we may get this DELETE event after the ctid has been reused by a new session
	// and we don't want to remove that mapping from the session table
	if conntrack != nil && conntrack.Session != nil {
		conntrack.Session.removeFromSessionTable()
	}
}

// cleanConntrackTable cleans the conntrack table by removing stale entries
func cleanConntrackTable() {
	conntrackTableMutex.Lock()
	defer conntrackTableMutex.Unlock()

	for ctid, conntrack := range conntrackTable {
		conntrack.Guardian.RLock()
		// We use 10000 seconds because 7440 is the established idle tcp timeout default
		if time.Now().Sub(conntrack.LastActivityTime) > 10000*time.Second {
			// In theory this should never happen,
			// entries should be removed by DELETE events
			// otherwise they should be getting UPDATE events and the LastActivityTime
			// would be at least within interval seconds.
			// The the entry exists, the LastActivityTime is a long time ago
			// some constraint has failed
			// In reality sometimes we miss DELETE events (if the buffer fills)
			// so sometimes we do see this happen in the real world under heavy load
			logger.Warn("Removing stale (%v) conntrack entry [%d] %v\n", time.Now().Sub(conntrack.LastActivityTime), ctid, conntrack.ClientSideTuple)
			if conntrack != nil && conntrack.Session != nil {
				conntrack.Session.flushDict()
				conntrack.Session.removeFromSessionTable()
			}
			delete(conntrackTable, ctid)
		}
		conntrack.Guardian.RUnlock()
	}
}

// createConntrack creates a new conntrack entry
func createConntrack(ctid uint32, connmark uint32, family uint8, eventType uint8, protocol uint8,
	client net.IP, server net.IP, clientPort uint16, serverPort uint16,
	clientNew net.IP, serverNew net.IP, clientPortNew uint16, serverPortNew uint16,
	clientBytes uint64, serverBytes uint64, clientPackets uint64, serverPackets uint64,
	timestampStart uint64, timestampStop uint64, timeout uint32, tcpState uint8) *Conntrack {
	conntrack := new(Conntrack)
	conntrack.ConntrackID = ctid
	conntrack.ConnMark = connmark
	conntrack.CreationTime = time.Now()
	conntrack.Family = family
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
	conntrack.ClientBytes = clientBytes
	conntrack.ServerBytes = serverBytes
	conntrack.TotalBytes = serverBytes + clientBytes
	conntrack.ClientPackets = clientPackets
	conntrack.ServerPackets = serverPackets
	conntrack.TotalPackets = serverPackets + clientPackets
	conntrack.TimeoutSeconds = timeout
	conntrack.TimestampStart = timestampStart
	conntrack.TimestampStop = timestampStop
	conntrack.TCPState = tcpState

	return conntrack
}

// updateStatsAndRates updates all the Byte and Packet counters and rates
// provided the new total counts, and the seconds since the last update
func updateStatsAndRates(conntrack *Conntrack, clientBytes uint64, serverBytes uint64, clientPackets uint64, serverPackets uint64, secondsSinceLastUpdate float32) {
	oldClientBytes := conntrack.ClientBytes
	oldServerBytes := conntrack.ServerBytes
	oldTotalBytes := conntrack.TotalBytes
	newClientBytes := clientBytes
	newServerBytes := serverBytes
	newTotalBytes := (newClientBytes + newServerBytes)
	diffClientBytes := (newClientBytes - oldClientBytes)
	diffServerBytes := (newServerBytes - oldServerBytes)
	diffTotalBytes := (newTotalBytes - oldTotalBytes)

	oldClientPackets := conntrack.ClientPackets
	oldServerPackets := conntrack.ServerPackets
	oldTotalPackets := conntrack.TotalPackets
	newClientPackets := clientPackets
	newServerPackets := serverPackets
	newTotalPackets := (newClientPackets + newServerPackets)
	diffClientPackets := (newClientPackets - oldClientPackets)
	diffServerPackets := (newServerPackets - oldServerPackets)
	diffTotalPackets := (newTotalPackets - oldTotalPackets)

	// In some cases, specifically UDP, a new session takes the place of an old session with the same tuple.
	// In this case the counts go down because its actually a new session. If the total Bytes is low, this
	// is probably the case so treat it as a new conntrack.
	if diffClientBytes < 0 || diffServerBytes < 0 || diffClientPackets < 0 || diffServerPackets < 0 {
		newClientBytes = clientBytes
		diffClientBytes = newClientBytes
		newServerBytes = serverBytes
		diffServerBytes = newServerBytes
		newTotalBytes = (newClientBytes + newServerBytes)
		diffTotalBytes = newTotalBytes

		newClientPackets = clientPackets
		diffClientPackets = newClientPackets
		newServerPackets = serverPackets
		diffServerPackets = newServerPackets
		newTotalPackets = (newClientPackets + newServerPackets)
		diffTotalPackets = newTotalPackets
	}

	clientRate := float32(diffClientBytes) / secondsSinceLastUpdate
	serverRate := float32(diffServerBytes) / secondsSinceLastUpdate
	totalRate := float32(diffTotalBytes) / secondsSinceLastUpdate

	clientPacketRate := float32(diffClientPackets) / secondsSinceLastUpdate
	serverPacketRate := float32(diffServerPackets) / secondsSinceLastUpdate
	totalPacketRate := float32(diffTotalPackets) / secondsSinceLastUpdate

	conntrack.ClientBytes = newClientBytes
	conntrack.ServerBytes = newServerBytes
	conntrack.TotalBytes = newTotalBytes
	conntrack.ClientBytesDiff = diffClientBytes
	conntrack.ServerBytesDiff = diffServerBytes
	conntrack.TotalBytesDiff = diffTotalBytes
	conntrack.ClientByteRate = clientRate
	conntrack.ServerByteRate = serverRate
	conntrack.TotalByteRate = totalRate

	conntrack.ClientPackets = newClientPackets
	conntrack.ServerPackets = newServerPackets
	conntrack.TotalPackets = newTotalPackets
	conntrack.ClientPacketsDiff = diffClientPackets
	conntrack.ServerPacketsDiff = diffServerPackets
	conntrack.TotalPacketsDiff = diffTotalPackets
	conntrack.ClientPacketRate = clientPacketRate
	conntrack.ServerPacketRate = serverPacketRate
	conntrack.TotalPacketRate = totalPacketRate
}
