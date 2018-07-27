package dispatch

import (
	"github.com/untangle/packetd/services/logger"
	"net"
	"strconv"
	"sync"
	"time"
)

// ConntrackEntry stores the details of a conntrack entry
type ConntrackEntry struct {
	ConntrackID      uint32
	Session          *SessionEntry
	SessionID        uint64
	CreationTime     time.Time
	LastActivityTime time.Time
	ClientSideTuple  Tuple
	ServerSideTuple  Tuple
	EventCount       uint64
	C2Sbytes         uint64
	S2Cbytes         uint64
	TotalBytes       uint64
	C2Srate          float32
	S2Crate          float32
	TotalRate        float32
	PurgeFlag        bool
}

//ConntrackHandlerFunction defines a pointer to a conntrack callback function
type ConntrackHandlerFunction func(int, *ConntrackEntry)

var conntrackList map[string]SubscriptionHolder
var conntrackListMutex sync.Mutex
var conntrackTable map[uint32]*ConntrackEntry
var conntrackTableMutex sync.Mutex

// String returns string representation of conntrack
func (c ConntrackEntry) String() string {
	return strconv.Itoa(int(c.ConntrackID)) + "|" + c.ClientSideTuple.String()
}

// InsertConntrackSubscription adds a subscription for receiving conntrack messages
func InsertConntrackSubscription(owner string, priority int, function ConntrackHandlerFunction) {
	var holder SubscriptionHolder
	logger.Info("Adding Conntrack Event Subscription (%s, %d)\n", owner, priority)

	holder.Owner = owner
	holder.Priority = priority
	holder.ConntrackFunc = function
	conntrackListMutex.Lock()
	conntrackList[owner] = holder
	conntrackListMutex.Unlock()
}

// conntrackCallback is the global conntrack event handler
func conntrackCallback(ctid uint32, family uint8, eventType uint8, protocol uint8,
	client net.IP, server net.IP, clientPort uint16, serverPort uint16,
	clientNew net.IP, serverNew net.IP, clientPortNew uint16, serverPortNew uint16,
	c2sBytes uint64, s2cBytes uint64) {

	var conntrackEntry *ConntrackEntry
	var conntrackEntryFound bool

	// If we already have a conntrackEntry update the existing, otherwise create a new conntrackEntry for the table.
	conntrackEntry, conntrackEntryFound = findConntrackEntry(ctid)

	if conntrackEntryFound {
		conntrackEntry.EventCount++
		logger.Trace("conntrack event[%d,%c]: %s \n", ctid, eventType, conntrackEntry.ClientSideTuple)
	} else {
		conntrackEntry = new(ConntrackEntry)
		conntrackEntry.ConntrackID = ctid
		conntrackEntry.SessionID = nextSessionID()
		conntrackEntry.CreationTime = time.Now()
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
		conntrackEntry.EventCount = 1

		logger.Trace("conntrack event[%d,%c]: %v \n", ctid, eventType, conntrackEntry.ClientSideTuple)

		session, _ := findSessionEntry(uint32(ctid))
		if session != nil {
			if session.ClientSideTuple.Equal(conntrackEntry.ClientSideTuple) {
				session.ServerSideTuple.Protocol = protocol
				session.ServerSideTuple.ClientAddress = dupIP(clientNew)
				session.ServerSideTuple.ClientPort = clientPortNew
				session.ServerSideTuple.ServerAddress = dupIP(serverNew)
				session.ServerSideTuple.ServerPort = serverPortNew
				session.ConntrackConfirmed = true
				conntrackEntry.Session = session
			} else {
				//session does not match conntrack event
				//this happens when we receive packets that never got conntrack confirmed
				//those conntrack IDs get re-used instantly
				//however, if this was conntrack confirmed - something is very wrong
				//and we seem to be re-using conntrack IDs when not expected!
				var logLevel int
				logLevel = logger.LogLevelDebug
				if session.ConntrackConfirmed {
					// if conntrack has been confirmed, this is an error
					// so increase log level
					logLevel = logger.LogLevelErr
				}
				if logger.IsLogEnabled(logLevel) {
					logger.LogMessage(logLevel, "Conntrack Mismatch! %d\n", ctid)
					logger.LogMessage(logLevel, "  Packet     Tuple: %s\n", conntrackEntry.ClientSideTuple)
					logger.LogMessage(logLevel, "  ClientSide Tuple: %s\n", session.ClientSideTuple)
				}

				if session.ConntrackConfirmed {
					panic("CONNTRACK ID RE-USE DETECTED")
				}
				logger.Debug("Removing stale session %d %v\n", ctid, session.ClientSideTuple)
				removeSessionEntry(ctid)
				session = nil
			}
		}
		insertConntrackEntry(ctid, conntrackEntry)
	}

	conntrackEntry.LastActivityTime = time.Now()

	// handle DELETE events
	if eventType == 'D' {
		conntrackEntry.PurgeFlag = true
		if conntrackEntry.Session != nil {
			removeSessionEntry(ctid)
		}
		removeConntrackEntry(ctid)
	} else {
		conntrackEntry.PurgeFlag = false
	}

	// handle UPDATE events
	if eventType == 'U' {
		oldC2sBytes := conntrackEntry.C2Sbytes
		oldS2cBytes := conntrackEntry.S2Cbytes
		oldTotalBytes := conntrackEntry.TotalBytes
		newC2sBytes := c2sBytes
		newS2cBytes := s2cBytes
		newTotalBytes := (newC2sBytes + newS2cBytes)
		diffC2sBytes := (newC2sBytes - oldC2sBytes)
		diffS2cBytes := (newS2cBytes - oldS2cBytes)
		diffTotalBytes := (newTotalBytes - oldTotalBytes)

		// In some cases, specifically UDP, a new session takes the place of an old session with the same tuple.
		// In this case the counts go down because its actually a new session. If the total bytes is low, this
		// is probably the case so treat it as a new conntrackEntry.
		if (diffC2sBytes < 0) || (diffS2cBytes < 0) {
			newC2sBytes = c2sBytes
			diffC2sBytes = newC2sBytes
			newS2cBytes = s2cBytes
			diffS2cBytes = newS2cBytes
			newTotalBytes = (newC2sBytes + newS2cBytes)
			diffTotalBytes = newTotalBytes
			return
		}

		c2sRate := float32(diffC2sBytes / 60)
		s2cRate := float32(diffS2cBytes / 60)
		totalRate := float32(diffTotalBytes / 60)

		conntrackEntry.C2Sbytes = newC2sBytes
		conntrackEntry.S2Cbytes = newS2cBytes
		conntrackEntry.TotalBytes = newTotalBytes
		conntrackEntry.C2Srate = c2sRate
		conntrackEntry.S2Crate = s2cRate
		conntrackEntry.TotalRate = totalRate
	}

	// We loop and increment the priority until all subscriptions have been called
	sublist := conntrackList
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
	conntrackTableMutex.Lock()
	defer conntrackTableMutex.Unlock()
	conntrackTable[finder] = entry
}

// removeConntrackEntry removes an entry from the conntrack table
func removeConntrackEntry(finder uint32) {
	logger.Trace("Remove conntrack ctid %d\n", finder)
	conntrackTableMutex.Lock()
	defer conntrackTableMutex.Unlock()
	delete(conntrackTable, finder)
}

// cleanConntrackTable cleans the conntrack table by removing stale entries
func cleanConntrackTable() {
	nowtime := time.Now()

	for key, val := range conntrackTable {
		if val.PurgeFlag == false {
			continue
		}
		if (nowtime.Unix() - val.LastActivityTime.Unix()) < 600 {
			continue
		}
		removeConntrackEntry(key)
		// this should never happen, so print an error
		logger.Err("Removing stale conntrack entry %d %v\n", key, val.ClientSideTuple)
	}
}
