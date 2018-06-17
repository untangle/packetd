package support

import (
	"crypto/x509"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/untangle/packetd/services/logger"
	"net"
	"os/exec"
	"sync"
	"time"
)

//NetfilterHandlerFunction defines a pointer to a netfilter callback function
type NetfilterHandlerFunction func(chan<- SubscriptionResult, TrafficMessage, uint)

//ConntrackHandlerFunction defines a pointer to a conntrack callback function
type ConntrackHandlerFunction func(int, *ConntrackEntry)

//NetloggerHandlerFunction defines a pointer to a netlogger callback function
type NetloggerHandlerFunction func(*NetloggerMessage)

var netfilterList map[string]SubscriptionHolder
var conntrackList map[string]SubscriptionHolder
var netloggerList map[string]SubscriptionHolder
var netfilterListMutex sync.Mutex
var conntrackListMutex sync.Mutex
var netloggerListMutex sync.Mutex

var appname = "support"
var runtime time.Time
var sessionTable map[uint32]SessionEntry
var conntrackTable map[uint32]ConntrackEntry
var conntrackMutex sync.Mutex
var sessionMutex sync.Mutex
var sessionIndex uint64
var shutdownChannel = make(chan bool)

//-----------------------------------------------------------------------------

// SubscriptionHolder stores the details of a data callback subscription
type SubscriptionHolder struct {
	Owner         string
	Priority      int
	NetfilterFunc NetfilterHandlerFunction
	ConntrackFunc ConntrackHandlerFunction
	NetloggerFunc NetloggerHandlerFunction
}

//-----------------------------------------------------------------------------

// SubscriptionResult returns status and other information from a subscription handler function
type SubscriptionResult struct {
	Owner          string
	PacketMark     uint32
	SessionRelease bool
}

//-----------------------------------------------------------------------------

// SessionEntry stores details related to a session
type SessionEntry struct {
	SessionID          uint64
	SessionCreation    time.Time
	SessionActivity    time.Time
	ClientSideTuple    Tuple
	ServerSideTuple    Tuple
	SessionCertificate x509.Certificate
	UpdateCount        uint64
	NetfilterSubs      map[string]SubscriptionHolder
}

//-----------------------------------------------------------------------------

// Tuple represent a session using the protocol and source and destination
// address and port values.
type Tuple struct {
	Protocol   uint8
	ClientAddr net.IP
	ClientPort uint16
	ServerAddr net.IP
	ServerPort uint16
}

//-----------------------------------------------------------------------------

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

//-----------------------------------------------------------------------------

// TrafficMessage is used to pass netfilter traffic to interested plugins
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

//-----------------------------------------------------------------------------

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

//-----------------------------------------------------------------------------

// Startup is called during daemon startup to handle initialization
func Startup() {
	// create the session, conntrack, and certificate tables
	sessionTable = make(map[uint32]SessionEntry)
	conntrackTable = make(map[uint32]ConntrackEntry)

	// create the netfilter, conntrack, and netlogger subscription tables
	netfilterList = make(map[string]SubscriptionHolder)
	conntrackList = make(map[string]SubscriptionHolder)
	netloggerList = make(map[string]SubscriptionHolder)

	// initialize the sessionIndex counter
	// highest 16 bits are zero
	// middle  32 bits should be epoch
	// lowest  16 bits are zero
	// this means that sessionIndex should be ever increasing despite restarts
	// (unless there are more than 16 bits or 65k sessions per sec on average)
	sessionIndex = ((uint64(runtime.Unix()) & 0xFFFFFFFF) << 16)

	go periodicTask()
}

// Shutdown any support services
func Shutdown() {
	// Send shutdown signal to periodicTask and wait for it to return
	shutdownChannel <- true
	select {
	case <-shutdownChannel:
	case <-time.After(10 * time.Second):
		logger.LogMessage(logger.LogErr, appname, "Failed to properly shutdown periodicTask\n")
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

// CleanSessionTable cleans the session table by removing stale entries
func CleanSessionTable() {
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

// CleanConntrackTable cleans the conntrack table by removing stale entries
func CleanConntrackTable() {
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

// InsertNetfilterSubscription adds a subscription for receiving netfilter messages
func InsertNetfilterSubscription(owner string, priority int, function NetfilterHandlerFunction) {
	var holder SubscriptionHolder

	holder.Owner = owner
	holder.Priority = priority
	holder.NetfilterFunc = function
	netfilterListMutex.Lock()
	netfilterList[owner] = holder
	netfilterListMutex.Unlock()
}

//-----------------------------------------------------------------------------

// InsertConntrackSubscription adds a subscription for receiving conntrack messages
func InsertConntrackSubscription(owner string, priority int, function ConntrackHandlerFunction) {
	var holder SubscriptionHolder

	holder.Owner = owner
	holder.Priority = priority
	holder.ConntrackFunc = function
	conntrackListMutex.Lock()
	conntrackList[owner] = holder
	conntrackListMutex.Unlock()
}

//-----------------------------------------------------------------------------

// InsertNetloggerSubscription adds a subscription for receiving netlogger messages
func InsertNetloggerSubscription(owner string, priority int, function NetloggerHandlerFunction) {
	var holder SubscriptionHolder

	holder.Owner = owner
	holder.Priority = priority
	holder.NetloggerFunc = function
	netloggerListMutex.Lock()
	netloggerList[owner] = holder
	netloggerListMutex.Unlock()
}

//-----------------------------------------------------------------------------

// AttachNetfilterSubscriptions attaches active netfilter subscriptions to the argumented SessionEntry
func AttachNetfilterSubscriptions(session *SessionEntry) {
	session.NetfilterSubs = make(map[string]SubscriptionHolder)

	for index, element := range netfilterList {
		session.NetfilterSubs[index] = element
	}
}

//-----------------------------------------------------------------------------

// GetConntrackSubscriptions returns the list of active conntrack subscriptions
func GetConntrackSubscriptions() map[string]SubscriptionHolder {
	return conntrackList
}

//-----------------------------------------------------------------------------

// GetNetloggerSubscriptions returns the list of active netlogger subscriptions
func GetNetloggerSubscriptions() map[string]SubscriptionHolder {
	return netloggerList
}

// Run a system command
func SystemCommand(command string, arguments []string) ([]byte, error) {
	var result []byte
	var err error

	result, err = exec.Command(command, arguments...).CombinedOutput()
	if err != nil {
		logger.LogMessage(logger.LogInfo, appname, "COMMAND:%s | OUTPUT:%s | ERROR:%s\n", command, string(result), err.Error())
	} else {
		logger.LogMessage(logger.LogDebug, appname, "COMMAND:%s | OUTPUT:%s\n", command, string(result))
	}
	return result, err
}

// FIXME this should be split into separate tasks in separate services
func periodicTask() {
	var counter int

	for {
		select {
		case <-shutdownChannel:
			shutdownChannel <- true
			return
		case <-time.After(60 * time.Second):
			counter++
			logger.LogMessage(logger.LogDebug, appname, "Calling periodic support task %d\n", counter)
			CleanSessionTable()   //FIXME move to session service
			CleanConntrackTable() //FIXME move to conntrack service
		}
	}
}
