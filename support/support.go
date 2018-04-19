package support

import "fmt"
import "net"
import "time"
import "sync"

var runtime time.Time
var conntrackTable map[string]ConntrackEntry
var sessionMutex sync.Mutex
var sessionIndex uint64

/*---------------------------------------------------------------------------*/
type Tuple  struct {
	Protocol			uint8
	ClientAddr			net.IP
	ClientPort			uint16
	ServerAddr			net.IP
	ServerPort			uint16
}

/*---------------------------------------------------------------------------*/
type ConntrackEntry struct {
	SessionId			uint64
	SessionCreation		time.Time
	SessionTuple		Tuple
	UpdateCount			uint64
	C2Sbytes			uint64
	S2Cbytes			uint64
	TotalBytes			uint64
	C2Srate				float32
	S2Crate				float32
	TotalRate			float32
}

/*---------------------------------------------------------------------------*/
type Logger struct {
	Protocol 	uint8
	IcmpType	uint16
	SrcIntf		uint8
	DstIntf		uint8
	SrcAddr		uint32
	DstAddr		uint32
	SrcPort		uint16
	DstPort		uint16
	Mark		uint32
	Prefix		string
}

/*---------------------------------------------------------------------------*/
func Startup() {
	// capture startup time
	runtime = time.Now()

	// create the conntrack table
	conntrackTable = make(map[string]ConntrackEntry)

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
	ip[1] = byte(value >>8)
	ip[2] = byte(value >>16)
	ip[3] = byte(value >> 24)
	return(ip)
}

/*---------------------------------------------------------------------------*/
func Tuple2String(tuple Tuple) string {
	retval := fmt.Sprintf("%d|%s:%d-%s:%d",tuple.Protocol,tuple.ClientAddr,tuple.ClientPort,tuple.ServerAddr,tuple.ServerPort)
	return(retval)
}

/*---------------------------------------------------------------------------*/
func NextSessionId() uint64 {
	var value uint64
	sessionMutex.Lock()
	value = sessionIndex
	sessionIndex++

	if (sessionIndex == 0) {
		sessionIndex++
	}

	sessionMutex.Unlock()
	return(value)
}
/*---------------------------------------------------------------------------*/
func FindConntrackEntry(finder string) (ConntrackEntry, bool) {
	entry, status := conntrackTable[finder]
	return entry, status
}

/*---------------------------------------------------------------------------*/
func InsertConntrackEntry(finder string, entry ConntrackEntry) {
	conntrackTable[finder] = entry
}

/*---------------------------------------------------------------------------*/
