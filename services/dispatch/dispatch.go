package dispatch

import (
	"crypto/x509"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/untangle/packetd/services/kernel"
	"github.com/untangle/packetd/services/logger"
	"github.com/untangle/packetd/services/reports"
	"net"
	"sync"
	"time"
)

//NfqueueHandlerFunction defines a pointer to a nfqueue callback function
type NfqueueHandlerFunction func(chan<- SubscriptionResult, TrafficMessage, uint)

//ConntrackHandlerFunction defines a pointer to a conntrack callback function
type ConntrackHandlerFunction func(int, *ConntrackEntry)

//NetloggerHandlerFunction defines a pointer to a netlogger callback function
type NetloggerHandlerFunction func(*NetloggerMessage)

// SubscriptionHolder stores the details of a data callback subscription
type SubscriptionHolder struct {
	Owner         string
	Priority      int
	NfqueueFunc   NfqueueHandlerFunction
	ConntrackFunc ConntrackHandlerFunction
	NetloggerFunc NetloggerHandlerFunction
}

// SubscriptionResult returns status and other information from a subscription handler function
type SubscriptionResult struct {
	Owner          string
	PacketMark     uint32
	SessionRelease bool
}

// SessionEntry stores details related to a session
type SessionEntry struct {
	SessionID          uint64
	SessionCreation    time.Time
	SessionActivity    time.Time
	ClientSideTuple    Tuple
	ServerSideTuple    Tuple
	SessionCertificate x509.Certificate
	UpdateCount        uint64
	Subs               map[string]SubscriptionHolder
}

// Tuple represent a session using the protocol and source and destination address and port values.
type Tuple struct {
	Protocol   uint8
	ClientAddr net.IP
	ClientPort uint16
	ServerAddr net.IP
	ServerPort uint16
}

// ConntrackEntry stores the details of a conntrack entry
type ConntrackEntry struct {
	ConntrackID     uint32
	SessionID       uint64
	SessionCreation time.Time
	SessionActivity time.Time
	ClientSideTuple Tuple
	ServerSideTuple Tuple
	UpdateCount     uint64
	C2Sbytes        uint64
	S2Cbytes        uint64
	TotalBytes      uint64
	C2Srate         float32
	S2Crate         float32
	TotalRate       float32
	PurgeFlag       bool
}

// TrafficMessage is used to pass nfqueue traffic to interested plugins
type TrafficMessage struct {
	Session  SessionEntry
	Tuple    Tuple
	Packet   gopacket.Packet
	Length   int
	IPlayer  *layers.IPv4
	TCPlayer *layers.TCP
	UDPlayer *layers.UDP
	Payload  []byte
}

// NetloggerMessage is used to pass the details of NFLOG events to interested plugins
type NetloggerMessage struct {
	Version  uint8
	Protocol uint8
	IcmpType uint16
	SrcIntf  uint8
	DstIntf  uint8
	SrcAddr  string
	DstAddr  string
	SrcPort  uint16
	DstPort  uint16
	Mark     uint32
	Prefix   string
}

var nfqueueList map[string]SubscriptionHolder
var conntrackList map[string]SubscriptionHolder
var netloggerList map[string]SubscriptionHolder
var nfqueueListMutex sync.Mutex
var conntrackListMutex sync.Mutex
var netloggerListMutex sync.Mutex
var sessionTable map[uint32]SessionEntry
var conntrackTable map[uint32]ConntrackEntry
var conntrackMutex sync.Mutex
var sessionMutex sync.Mutex
var sessionIndex uint64
var shutdownCleanerTask = make(chan bool)
var appname = "dispatch"

// Startup starts the event handling service
func Startup() {
	// create the session, conntrack, and certificate tables
	sessionTable = make(map[uint32]SessionEntry)
	conntrackTable = make(map[uint32]ConntrackEntry)

	// create the nfqueue, conntrack, and netlogger subscription tables
	nfqueueList = make(map[string]SubscriptionHolder)
	conntrackList = make(map[string]SubscriptionHolder)
	netloggerList = make(map[string]SubscriptionHolder)

	// initialize the sessionIndex counter
	// highest 16 bits are zero
	// middle  32 bits should be epoch
	// lowest  16 bits are zero
	// this means that sessionIndex should be ever increasing despite restarts
	// (unless there are more than 16 bits or 65k sessions per sec on average)
	sessionIndex = ((uint64(time.Now().Unix()) & 0xFFFFFFFF) << 16)

	kernel.RegisterConntrackCallback(conntrackCallback)
	kernel.RegisterNfqueueCallback(nfqueueCallback)
	kernel.RegisterNetloggerCallback(netloggerCallback)

	// start cleaner tasks to clean tables
	go cleanerTask()
}

// Shutdown stops the event handling service
func Shutdown() {
	// Send shutdown signal to periodicTask and wait for it to return
	shutdownCleanerTask <- true
	select {
	case <-shutdownCleanerTask:
	case <-time.After(10 * time.Second):
		logger.LogMessage(logger.LogErr, appname, "Failed to properly shutdown cleanerTask\n")
	}
}

// NextSessionID returns the next sequential session ID value
func NextSessionID() uint64 {
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

// FindSessionEntry searches for an entry in the session table
func FindSessionEntry(finder uint32) (SessionEntry, bool) {
	sessionMutex.Lock()
	entry, status := sessionTable[finder]
	sessionMutex.Unlock()
	return entry, status
}

// InsertSessionEntry adds an entry to the session table
func InsertSessionEntry(finder uint32, entry SessionEntry) {
	sessionMutex.Lock()
	sessionTable[finder] = entry
	sessionMutex.Unlock()
}

// RemoveSessionEntry removes an entry from the session table
func RemoveSessionEntry(finder uint32) {
	sessionMutex.Lock()
	delete(sessionTable, finder)
	sessionMutex.Unlock()
}

// FindConntrackEntry finds an entry in the conntrack table
func FindConntrackEntry(finder uint32) (ConntrackEntry, bool) {
	conntrackMutex.Lock()
	entry, status := conntrackTable[finder]
	conntrackMutex.Unlock()
	return entry, status
}

// InsertConntrackEntry adds an entry to the conntrack table
func InsertConntrackEntry(finder uint32, entry ConntrackEntry) {
	conntrackMutex.Lock()
	conntrackTable[finder] = entry
	conntrackMutex.Unlock()
}

// RemoveConntrackEntry removes an entry from the conntrack table
func RemoveConntrackEntry(finder uint32) {
	conntrackMutex.Lock()
	delete(conntrackTable, finder)
	conntrackMutex.Unlock()
}

// InsertNfqueueSubscription adds a subscription for receiving nfqueue messages
func InsertNfqueueSubscription(owner string, priority int, function NfqueueHandlerFunction) {
	var holder SubscriptionHolder
	logger.LogMessage(logger.LogInfo, appname, "Adding NFQueue Event Subscription (%s, %d)\n", owner, priority)

	holder.Owner = owner
	holder.Priority = priority
	holder.NfqueueFunc = function
	nfqueueListMutex.Lock()
	nfqueueList[owner] = holder
	nfqueueListMutex.Unlock()
}

// InsertConntrackSubscription adds a subscription for receiving conntrack messages
func InsertConntrackSubscription(owner string, priority int, function ConntrackHandlerFunction) {
	var holder SubscriptionHolder
	logger.LogMessage(logger.LogInfo, appname, "Adding Conntrack Event Subscription (%s, %d)\n", owner, priority)

	holder.Owner = owner
	holder.Priority = priority
	holder.ConntrackFunc = function
	conntrackListMutex.Lock()
	conntrackList[owner] = holder
	conntrackListMutex.Unlock()
}

// InsertNetloggerSubscription adds a subscription for receiving netlogger messages
func InsertNetloggerSubscription(owner string, priority int, function NetloggerHandlerFunction) {
	var holder SubscriptionHolder
	logger.LogMessage(logger.LogInfo, appname, "Adding Netlogger Event Subscription (%s, %d)\n", owner, priority)

	holder.Owner = owner
	holder.Priority = priority
	holder.NetloggerFunc = function
	netloggerListMutex.Lock()
	netloggerList[owner] = holder
	netloggerListMutex.Unlock()
}

// AttachNfqueueSubscriptions attaches active nfqueue subscriptions to the argumented SessionEntry
func AttachNfqueueSubscriptions(session *SessionEntry) {
	session.Subs = make(map[string]SubscriptionHolder)

	for index, element := range nfqueueList {
		session.Subs[index] = element
	}
}

// GetConntrackSubscriptions returns the list of active conntrack subscriptions
func GetConntrackSubscriptions() map[string]SubscriptionHolder {
	return conntrackList
}

// GetNetloggerSubscriptions returns the list of active netlogger subscriptions
func GetNetloggerSubscriptions() map[string]SubscriptionHolder {
	return netloggerList
}

func conntrackCallback(ctid uint32, eventType uint8, protocol uint8,
	client net.IP, server net.IP, clientPort uint16, serverPort uint16,
	clientNew net.IP, serverNew net.IP, clientPortNew uint16, serverPortNew uint16,
	c2sBytes uint64, s2cBytes uint64) {
	var clientSideTuple Tuple
	var serverSideTuple Tuple

	session, sessionFound := FindSessionEntry(uint32(ctid))

	// FIXME, This can be removed if we are sure this never happens.
	// This is temporary and is used to look for conntrack id's being re-used
	// unexpectedly. On the first packet, the nfqueue handler seems to get
	// called first, before the conntrack handler, so we use the ctid in that
	// handler to create the session entry. It's possible we'll get the
	// conntrack NEW message before the session gets added by the other
	// handler, so we don't care if the session is not found, but if we find
	// the session and the update count is greater than one, it likely means a
	// conntrack ID has been reused, and we need to re-think some things.
	if eventType == 'N' && sessionFound && session.UpdateCount != 1 {
		// FIXME, I suspect on a multi-core machine, it is possible to process 2 packets before conntrack NEW
		// in this case, this would fire, but not be a reused conntrack ID - dmorris
		logger.LogMessage(logger.LogWarn, appname, "Unexperted update Count %d for Session %d\n", session.UpdateCount, ctid)
		panic("CONNTRACK ID RE-USE DETECTED")
	}

	// If we already have a conntrackEntry update the existing, otherwise create a new conntrackEntry for the table.
	conntrackEntry, conntrackEntryFound := FindConntrackEntry(ctid)
	if conntrackEntryFound {
		logger.LogMessage(logger.LogDebug, appname, "CONNTRACK Found %d in table\n", ctid)
		conntrackEntry.UpdateCount++
	} else {
		conntrackEntry.ConntrackID = ctid
		conntrackEntry.SessionID = NextSessionID()
		conntrackEntry.SessionCreation = time.Now()
		conntrackEntry.ClientSideTuple = clientSideTuple
		conntrackEntry.UpdateCount = 1
		InsertConntrackEntry(ctid, conntrackEntry)
	}

	conntrackEntry.SessionActivity = time.Now()

	// handle NEW events
	if eventType == 'N' {
		if sessionFound {
			// Set the server side tuple, this is the first time we've seen the post-NAT data
			session.ServerSideTuple = serverSideTuple

			columns := map[string]interface{}{
				"session_id": session.SessionID,
			}
			modifiedColumns := map[string]interface{}{
				"client_addr_new": session.ServerSideTuple.ClientAddr,
				"server_addr_new": session.ServerSideTuple.ServerAddr,
				"client_port_new": session.ServerSideTuple.ClientPort,
				"server_port_new": session.ServerSideTuple.ServerPort,
			}
			// FIXME move to logger plugin
			reports.LogEvent(reports.CreateEvent("session_nat", "sessions", 2, columns, modifiedColumns))
		} else {
			// We should not receive a new conntrack event for something that is not in the session table
			// However it happens on local outbound sessions, we should handle these diffently
			// FIXME log session_new event
		}
	}

	// handle DELETE events
	if eventType == 'D' {
		conntrackEntry.PurgeFlag = true
		logger.LogMessage(logger.LogDebug, appname, "SESSION Removing %d from table\n", ctid)
		RemoveSessionEntry(ctid)
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

		// FIXME log session_minutes event
	}

	// We loop and increment the priority until all subscribtions have been called
	sublist := GetConntrackSubscriptions()
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
			logger.LogMessage(logger.LogDebug, appname, "Calling conntrack APP:%s PRIORITY:%d\n", key, priority)
			wg.Add(1)
			go func(val SubscriptionHolder) {
				val.ConntrackFunc(int(eventType), &conntrackEntry)
				wg.Done()
			}(val)
			subcount++
		}

		// Wait on all of this priority to finish
		wg.Wait()

		// Increment the priority and keep looping until we've called all subscribers
		priority++
	}
}

// nfqueueCallback is the callback for the packet
// return the mark to set on the packet
func nfqueueCallback(ctid uint32, packet gopacket.Packet, packetLength int, pmark uint32) uint32 {
	var mess TrafficMessage

	type TrafficMessage struct {
		Session  SessionEntry
		Tuple    Tuple
		Packet   gopacket.Packet
		Length   int
		IPlayer  *layers.IPv4
		TCPlayer *layers.TCP
		UDPlayer *layers.UDP
		Payload  []byte
	}

	mess.Packet = packet
	mess.Length = packetLength

	// get the IPv4 layer
	ipLayer := mess.Packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return (pmark)
	}
	mess.IPlayer = ipLayer.(*layers.IPv4)

	mess.Tuple.Protocol = uint8(mess.IPlayer.Protocol)
	mess.Tuple.ClientAddr = mess.IPlayer.SrcIP
	mess.Tuple.ServerAddr = mess.IPlayer.DstIP

	// get the TCP layer
	tcpLayer := mess.Packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		mess.TCPlayer = tcpLayer.(*layers.TCP)
		mess.Tuple.ClientPort = uint16(mess.TCPlayer.SrcPort)
		mess.Tuple.ServerPort = uint16(mess.TCPlayer.DstPort)
	}

	// get the UDP layer
	udpLayer := mess.Packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		mess.UDPlayer = udpLayer.(*layers.UDP)
		mess.Tuple.ClientPort = uint16(mess.UDPlayer.SrcPort)
		mess.Tuple.ServerPort = uint16(mess.UDPlayer.DstPort)
	}

	// right now we only care about TCP and UDP
	// FIXME do we really?
	if (tcpLayer == nil) && (udpLayer == nil) {
		return (pmark)
	}

	// get the Application layer
	appLayer := mess.Packet.ApplicationLayer()
	if appLayer != nil {
		mess.Payload = appLayer.Payload()
	}

	var session SessionEntry
	var ok bool
	var newSession = false

	// If we already have a session entry update the existing, otherwise create a new entry for the table.
	if session, ok = FindSessionEntry(uint32(ctid)); ok {
		logger.LogMessage(logger.LogDebug, appname, "SESSION Found %d in table\n", ctid)
		session.SessionActivity = time.Now()
		session.UpdateCount++
	} else {
		logger.LogMessage(logger.LogDebug, appname, "SESSION Adding %d to table\n", ctid)
		newSession = true
		session.SessionID = NextSessionID()
		session.SessionCreation = time.Now()
		session.SessionActivity = time.Now()
		session.ClientSideTuple = mess.Tuple
		session.UpdateCount = 1
		AttachNfqueueSubscriptions(&session)
		InsertSessionEntry(uint32(ctid), session)
	}

	mess.Session = session

	pipe := make(chan SubscriptionResult)

	// We loop and increment the priority until all subscribtions have been called
	subtotal := len(session.Subs)
	subcount := 0
	priority := 0

	for subcount != subtotal {
		// Counts the total number of calls made for each priority so we know
		// how many SubscriptionResult's to read from the result channel
		hitcount := 0

		// Call all of the subscribed handlers for the current priority
		for key, val := range session.Subs {
			if val.Priority != priority {
				continue
			}
			logger.LogMessage(logger.LogDebug, appname, "Calling nfqueue APP:%s PRIORITY:%d\n", key, priority)
			go val.NfqueueFunc(pipe, mess, uint(ctid))
			hitcount++
			subcount++
		}

		// Add the mark bits returned from each handler and remove the session
		// subscription for any that set the SessionRelease flag
		for i := 0; i < hitcount; i++ {
			select {
			case result := <-pipe:
				pmark |= result.PacketMark
				if result.SessionRelease {
					logger.LogMessage(logger.LogDebug, appname, "Removing %s session nfqueue subscription for %d\n", result.Owner, uint32(ctid))
					delete(session.Subs, result.Owner)
				}
			}
		}

		// Increment the priority and keep looping until we've called all subscribers
		priority++
	}

	if newSession {
		// FIXME time_stamp
		// FIXME local_addr
		// FIXME remote_addr
		// FIXME client_intf
		// FIXME server_intf
		columns := map[string]interface{}{
			"session_id":  session.SessionID,
			"ip_protocol": session.ClientSideTuple.Protocol,
			"client_addr": session.ClientSideTuple.ClientAddr,
			"server_addr": session.ClientSideTuple.ServerAddr,
			"client_port": session.ClientSideTuple.ClientPort,
			"server_port": session.ClientSideTuple.ServerPort,
		}
		// FIXME move to logger plugin
		reports.LogEvent(reports.CreateEvent("session_new", "sessions", 1, columns, nil))
	}

	// return the updated mark to be set on the packet
	return (pmark)
}

func netloggerCallback(version uint8,
	protocol uint8, icmpType uint16,
	srcIntf uint8, dstIntf uint8,
	srcAddr string, dstAddr string,
	srcPort uint16, dstPort uint16, mark uint32, prefix string) {
	var netlogger NetloggerMessage

	netlogger.Version = version
	netlogger.Protocol = protocol
	netlogger.IcmpType = icmpType
	netlogger.SrcIntf = srcIntf
	netlogger.DstIntf = dstIntf
	netlogger.SrcAddr = srcAddr
	netlogger.DstAddr = dstAddr
	netlogger.SrcPort = srcPort
	netlogger.DstPort = dstPort
	netlogger.Mark = mark
	netlogger.Prefix = prefix

	// We loop and increment the priority until all subscribtions have been called
	sublist := GetNetloggerSubscriptions()
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
			logger.LogMessage(logger.LogDebug, appname, "Calling netlogger APP:%s PRIORITY:%d\n", key, priority)
			wg.Add(1)
			go func(val SubscriptionHolder) {
				val.NetloggerFunc(&netlogger)
				wg.Done()
			}(val)
			subcount++

		}

		// Wait on all of this priority to finish
		wg.Wait()

		// Increment the priority and keep looping until we've called all subscribers
		priority++
	}

}

// cleanConntrackTable cleans the conntrack table by removing stale entries
func cleanConntrackTable() {
	var counter int
	nowtime := time.Now()

	for key, val := range conntrackTable {
		if val.PurgeFlag == false {
			continue
		}
		if (nowtime.Unix() - val.SessionActivity.Unix()) < 60 {
			continue
		}
		RemoveConntrackEntry(key)
		counter++
		logger.LogMessage(logger.LogDebug, appname, "CONNTRACK Removing %d from table\n", key)
	}

	logger.LogMessage(logger.LogDebug, appname, "CONNTRACK REMOVED:%d REMAINING:%d\n", counter, len(conntrackTable))
}

// cleanSessionTable cleans the session table by removing stale entries
func cleanSessionTable() {
	var counter int
	nowtime := time.Now()

	for key, val := range sessionTable {
		if (nowtime.Unix() - val.SessionActivity.Unix()) < 60 {
			continue
		}
		RemoveSessionEntry(key)
		counter++
		logger.LogMessage(logger.LogDebug, appname, "SESSION Removing %s from table\n", key)
	}

	logger.LogMessage(logger.LogDebug, appname, "SESSION REMOVED:%d REMAINING:%d\n", counter, len(sessionTable))
}

// cleanerTask is a periodic task to cleanup conntrack and session tables
func cleanerTask() {
	var counter int

	for {
		select {
		case <-shutdownCleanerTask:
			shutdownCleanerTask <- true
			return
		case <-time.After(60 * time.Second):
			counter++
			logger.LogMessage(logger.LogDebug, appname, "Calling cleaner task %d\n", counter)
			cleanSessionTable()
			cleanConntrackTable()
		}
	}
}
