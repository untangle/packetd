package support

import (
	"bufio"
	"crypto/x509"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

const logConfigFile = "/tmp/logconfig.cfg"

var logLevelName = [...]string{"EMERG", "ALERT", "CRIT", "ERROR", "WARN", "NOTICE", "INFO", "DEBUG", "LOGIC"}
var appLogLevel map[string]int

//LogEmerg = stdlog.h/LOG_EMERG
const LogEmerg = 0

//LogAlert = stdlog.h/LOG_ALERT
const LogAlert = 1

//LogCrit = stdlog.h/LOG_CRIT
const LogCrit = 2

//LogErr = stdlog.h/LOG_ERR
const LogErr = 3

//LogWarn = stdlog.h/LOG_WARNING
const LogWarn = 4

//LogNotice = stdlog.h/LOG_NOTICE
const LogNotice = 5

//LogInfo = stdlog.h/LOG_INFO
const LogInfo = 6

//LogDebug = stdlog.h/LOG_DEBUG
const LogDebug = 7

//LogLogic = custom value
const LogLogic = 8

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
var certificateTable map[string]CertificateHolder
var certificateMutex sync.Mutex
var conntrackMutex sync.Mutex
var sessionMutex sync.Mutex
var sessionIndex uint64

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
	SessionTuple       Tuple
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
	SessionTuple    Tuple
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

// CertificateHolder is used to cache SSL/TLS certificates
type CertificateHolder struct {
	CreationTime time.Time
	Certificate  x509.Certificate
}

//-----------------------------------------------------------------------------

// Startup is called during daemon startup to handle initialization
func Startup() {
	// capture startup time
	runtime = time.Now()

	// create the map and load the LogMessage configuration
	appLogLevel = make(map[string]int)
	loadLoggerConfig()

	// create the session, conntrack, and certificate tables
	sessionTable = make(map[uint32]SessionEntry)
	conntrackTable = make(map[uint32]ConntrackEntry)
	certificateTable = make(map[string]CertificateHolder)

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
}

//-----------------------------------------------------------------------------

// LogMessage is called to write messages to the system log
func LogMessage(level int, source string, format string, args ...interface{}) {
	var ignore bool

	item, stat := appLogLevel[source]
	if stat == true {
		if item < level {
			ignore = true
		}
	}

	if ignore == true {
		return
	}

	nowtime := time.Now()
	var elapsed = nowtime.Sub(runtime)

	if len(args) == 0 {
		fmt.Printf("[%11.5f] %-6s %10s: %s", elapsed.Seconds(), logLevelName[level], source, format)
	} else {
		buffer := fmt.Sprintf(format, args...)
		fmt.Printf("[%11.5f] %-6s %10s: %s", elapsed.Seconds(), logLevelName[level], source, buffer)
	}
}

//-----------------------------------------------------------------------------

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

//-----------------------------------------------------------------------------

// FindSessionEntry searches for an entry in the session table
func FindSessionEntry(finder uint32) (SessionEntry, bool) {
	sessionMutex.Lock()
	entry, status := sessionTable[finder]
	sessionMutex.Unlock()
	return entry, status
}

//-----------------------------------------------------------------------------

// InsertSessionEntry adds an entry to the session table
func InsertSessionEntry(finder uint32, entry SessionEntry) {
	sessionMutex.Lock()
	sessionTable[finder] = entry
	sessionMutex.Unlock()
}

//-----------------------------------------------------------------------------

// RemoveSessionEntry removes an entry from the session table
func RemoveSessionEntry(finder uint32) {
	sessionMutex.Lock()
	delete(sessionTable, finder)
	sessionMutex.Unlock()
}

//-----------------------------------------------------------------------------

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
		LogMessage(LogDebug, appname, "SESSION Removing %s from table\n", key)
	}

	LogMessage(LogDebug, appname, "SESSION REMOVED:%d REMAINING:%d\n", counter, len(sessionTable))
}

//-----------------------------------------------------------------------------

// FindConntrackEntry finds an entry in the conntrack table
func FindConntrackEntry(finder uint32) (ConntrackEntry, bool) {
	conntrackMutex.Lock()
	entry, status := conntrackTable[finder]
	conntrackMutex.Unlock()
	return entry, status
}

//-----------------------------------------------------------------------------

// InsertConntrackEntry adds an entry to the conntrack table
func InsertConntrackEntry(finder uint32, entry ConntrackEntry) {
	conntrackMutex.Lock()
	conntrackTable[finder] = entry
	conntrackMutex.Unlock()
}

//-----------------------------------------------------------------------------

// RemoveConntrackEntry removes an entry from the conntrack table
func RemoveConntrackEntry(finder uint32) {
	conntrackMutex.Lock()
	delete(conntrackTable, finder)
	conntrackMutex.Unlock()
}

//-----------------------------------------------------------------------------

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
		LogMessage(LogDebug, appname, "CONNTRACK Removing %d from table\n", key)
	}

	LogMessage(LogDebug, appname, "CONNTRACK REMOVED:%d REMAINING:%d\n", counter, len(conntrackTable))
}

//-----------------------------------------------------------------------------

// FindCertificate fetches the cached certificate for the argumented address.
func FindCertificate(finder string) (x509.Certificate, bool) {
	certificateMutex.Lock()
	entry, status := certificateTable[finder]
	certificateMutex.Unlock()
	return entry.Certificate, status
}

//-----------------------------------------------------------------------------

// InsertCertificate adds a certificate to the cache
func InsertCertificate(finder string, cert x509.Certificate) {
	var holder CertificateHolder
	holder.CreationTime = time.Now()
	holder.Certificate = cert
	certificateMutex.Lock()
	certificateTable[finder] = holder
	certificateMutex.Unlock()
}

//-----------------------------------------------------------------------------

// RemoveCertificate removes a certificate from the cache
func RemoveCertificate(finder string) {
	certificateMutex.Lock()
	delete(certificateTable, finder)
	certificateMutex.Unlock()
}

//-----------------------------------------------------------------------------

// CleanCertificateTable cleans the certificate table by removing stale entries
func CleanCertificateTable() {
	var counter int
	nowtime := time.Now()

	for key, val := range certificateTable {
		if (nowtime.Unix() - val.CreationTime.Unix()) < 86400 {
			continue
		}
		RemoveCertificate(key)
		counter++
		LogMessage(LogDebug, appname, "CERTIFICATE Removing %s from table\n", key)
	}

	LogMessage(LogDebug, appname, "CERTIFICATE REMOVED:%d REMAINING:%d\n", counter, len(certificateTable))
}

//-----------------------------------------------------------------------------

// LogWriter is used to send an output stream to the LogMessage facility
type LogWriter struct {
	source string
	buffer []byte
}

//-----------------------------------------------------------------------------

// NewLogWriter creates an io Writer to steam output to the LogMessage facility
func NewLogWriter(source string) *LogWriter {
	return (&LogWriter{source, make([]byte, 256)})
}

//-----------------------------------------------------------------------------

// Write takes written data and stores it in a buffer and writes to the log when a line feed is detected
func (w *LogWriter) Write(p []byte) (int, error) {
	for _, b := range p {
		w.buffer = append(w.buffer, b)
		if b == '\n' {
			LogMessage(LogInfo, w.source, string(w.buffer))
			w.buffer = make([]byte, 256)
		}
	}

	return len(p), nil
}

//-----------------------------------------------------------------------------

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

//-----------------------------------------------------------------------------

func loadLoggerConfig() {
	var file *os.File
	var err error

	// open the logger configuration file
	file, err = os.Open(logConfigFile)

	// if there was an error create the config and try the open again
	if err != nil {
		initLoggerConfig()
		file, err = os.Open(logConfigFile)

		// if there is still an error we are out of options
		if err != nil {
			LogMessage(LogErr, appname, "Unable to load LogMessage configuration file: %s\n", logConfigFile)
			return
		}
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// ignore lines that start with an octothorpe
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}

		// split the line into the app and level
		pair := strings.Split(line, "=")
		if len(pair) != 2 {
			continue
		}

		// find numeric value for the level and put in map
		for index, value := range logLevelName {
			if strings.Compare(value, strings.ToUpper(pair[1])) == 0 {
				appLogLevel[pair[0]] = index
			}
		}
	}

	file.Close()
}

//-----------------------------------------------------------------------------

func initLoggerConfig() {
	file, err := os.Create(logConfigFile)
	if err != nil {
		return
	}

	LogMessage(LogAlert, appname, "LogMessage configuration not found. Creating default file: %s\n", logConfigFile)

	file.WriteString("# LogMessage configuration for packet daemon. One entry per line. Format:\n")
	file.WriteString("#   application=LEVEL\n")
	file.WriteString("# Valid log levels:\n")

	for item, element := range logLevelName {
		if item == 0 {
			file.WriteString("#   ")
		} else {
			file.WriteString(",")
		}

		file.WriteString(element)
	}
	file.WriteString("\n#\n")

	file.WriteString("certcache=INFO\n")
	file.WriteString("classify=INFO\n")
	file.WriteString("conndict=INFO\n")
	file.WriteString("conntrack=INFO\n")
	file.WriteString("dns=INFO\n")
	file.WriteString("example=INFO\n")
	file.WriteString("geoip=INFO\n")
	file.WriteString("netfilter=INFO\n")
	file.WriteString("netlogger=INFO\n")
	file.WriteString("packetd=INFO\n")
	file.WriteString("reports=INFO\n")
	file.WriteString("restd=INFO\n")
	file.WriteString("settings=INFO\n")
	file.WriteString("support=INFO\n")

	file.Close()
}

//-----------------------------------------------------------------------------
