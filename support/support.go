package support

import "fmt"
import "net"
import "time"
import "sync"
import "crypto/x509"

var runtime time.Time
var sessionTable map[string]SessionEntry
var conntrackTable map[string]ConntrackEntry
var certificateTable map[string]CertificateHolder
var certificateMutex sync.Mutex
var conntrackMutex sync.Mutex
var sessionMutex sync.Mutex
var sessionIndex uint64

/*---------------------------------------------------------------------------*/
type Tuple struct {
	Protocol   uint8
	ClientAddr net.IP
	ClientPort uint16
	ServerAddr net.IP
	ServerPort uint16
}

/*---------------------------------------------------------------------------*/
type SessionEntry struct {
	SessionId         uint64
	SessionCreation   time.Time
	SessionActivity   time.Time
	SessionTuple      Tuple
	UpdateCount       uint64
	ServerCertificate x509.Certificate
	ClientLocation    string
	ServerLocation    string
}

/*---------------------------------------------------------------------------*/
type ConntrackEntry struct {
	ConntrackId		uint
	SessionId       uint64
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

/*---------------------------------------------------------------------------*/
type Logger struct {
	Protocol uint8
	IcmpType uint16
	SrcIntf  uint8
	DstIntf  uint8
	SrcAddr  uint32
	DstAddr  uint32
	SrcPort  uint16
	DstPort  uint16
	Mark     uint32
	Prefix   string
}

/*---------------------------------------------------------------------------*/
type CertificateHolder struct {
	CreationTime time.Time
	Certificate  x509.Certificate
}

/*---------------------------------------------------------------------------*/
func Startup() {
	// capture startup time
	runtime = time.Now()

	// create the conntrack, session, and certificate tables
	conntrackTable = make(map[string]ConntrackEntry)
	sessionTable = make(map[string]SessionEntry)
	certificateTable = make(map[string]CertificateHolder)

	// initialize the sessionIndex counter
	// highest 16 bits are zero
	// middle  32 bits should be epoch
	// lowest  16 bits are zero
	// this means that sessionIndex should be ever increasing despite restarts
	// (unless there are more than 16 bits or 65k sessions per sec on average)
	sessionIndex = ((uint64(runtime.Unix()) & 0xFFFFFFFF) << 16)
}

/*---------------------------------------------------------------------------*/
func LogMessage(format string, args ...interface{}) {
	nowtime := time.Now()
	var elapsed = nowtime.Sub(runtime)

	if len(args) == 0 {
		fmt.Printf("[%.6f] %s", elapsed.Seconds(), format)
	} else {
		buffer := fmt.Sprintf(format, args...)
		fmt.Printf("[%.6f] %s", elapsed.Seconds(), buffer)
	}
}

/*---------------------------------------------------------------------------*/
func Int2Ip(value uint32) net.IP {
	ip := make(net.IP, 4)
	ip[0] = byte(value)
	ip[1] = byte(value >> 8)
	ip[2] = byte(value >> 16)
	ip[3] = byte(value >> 24)
	return (ip)
}

/*---------------------------------------------------------------------------*/
func Tuple2String(tuple Tuple) string {
	retval := fmt.Sprintf("%d|%s:%d-%s:%d", tuple.Protocol, tuple.ClientAddr, tuple.ClientPort, tuple.ServerAddr, tuple.ServerPort)
	return (retval)
}

/*---------------------------------------------------------------------------*/
func NextSessionId() uint64 {
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

/*---------------------------------------------------------------------------*/
func FindSessionEntry(finder string) (SessionEntry, bool) {
	sessionMutex.Lock()
	entry, status := sessionTable[finder]
	sessionMutex.Unlock()
	return entry, status
}

/*---------------------------------------------------------------------------*/
func InsertSessionEntry(finder string, entry SessionEntry) {
	sessionMutex.Lock()
	sessionTable[finder] = entry
	sessionMutex.Unlock()
}

/*---------------------------------------------------------------------------*/
func RemoveSessionEntry(finder string) {
	sessionMutex.Lock()
	delete(sessionTable, finder)
	sessionMutex.Unlock()
}

/*---------------------------------------------------------------------------*/
func CleanSessionTable() {
	var counter int = 0
	nowtime := time.Now()

	for key, val := range conntrackTable {
		if val.PurgeFlag == false {
			continue
		}
		if (nowtime.Unix() - val.SessionActivity.Unix()) < 60 {
			continue
		}
		RemoveSessionEntry(key)
		counter++
		LogMessage("SESSION Removing %s from table\n", key)
	}

	LogMessage("SESSION REMOVED:%d REMAINING:%d\n", counter, len(sessionTable))
}

/*---------------------------------------------------------------------------*/
func FindConntrackEntry(finder string) (ConntrackEntry, bool) {
	conntrackMutex.Lock()
	entry, status := conntrackTable[finder]
	conntrackMutex.Unlock()
	return entry, status
}

/*---------------------------------------------------------------------------*/
func InsertConntrackEntry(finder string, entry ConntrackEntry) {
	conntrackMutex.Lock()
	conntrackTable[finder] = entry
	conntrackMutex.Unlock()
}

/*---------------------------------------------------------------------------*/
func RemoveConntrackEntry(finder string) {
	conntrackMutex.Lock()
	delete(conntrackTable, finder)
	conntrackMutex.Unlock()
}

/*---------------------------------------------------------------------------*/
func CleanConntrackTable() {
	var counter int = 0
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
		LogMessage("CONNTRACK Removing %s from table\n", key)
	}

	LogMessage("CONNTRACK REMOVED:%d REMAINING:%d\n", counter, len(conntrackTable))
}

/*---------------------------------------------------------------------------*/
func FindCertificate(finder string) (x509.Certificate, bool) {
	certificateMutex.Lock()
	entry, status := certificateTable[finder]
	certificateMutex.Unlock()
	return entry.Certificate, status
}

/*---------------------------------------------------------------------------*/
func InsertCertificate(finder string, cert x509.Certificate) {
	var holder CertificateHolder
	holder.CreationTime = time.Now()
	holder.Certificate = cert
	certificateMutex.Lock()
	certificateTable[finder] = holder
	certificateMutex.Unlock()
}

/*---------------------------------------------------------------------------*/
func RemoveCertificate(finder string) {
	certificateMutex.Lock()
	delete(certificateTable, finder)
	certificateMutex.Unlock()
}

/*---------------------------------------------------------------------------*/
func CleanCertificateTable() {
	var counter int = 0
	nowtime := time.Now()

	for key, val := range certificateTable {
		if (nowtime.Unix() - val.CreationTime.Unix()) < 86400 {
			continue
		}
		RemoveCertificate(key)
		counter++
		LogMessage("CERTIFICATE Removing %s from table\n", key)
	}

	LogMessage("CERTIFICATE REMOVED:%d REMAINING:%d\n", counter, len(certificateTable))
}

/*---------------------------------------------------------------------------*/
