package stats

/*
	Functions to ping multiple target addresss from each local interface and calculate the latency.
	For each active WAN interface we open an net.IPConn and start a goroutine that listens
	for replies. The sequence number is used to lookup the transmit time, calculate the latency,
	and record it in the corresponding interface stats Collector.

	Crafted with bits and pieces pulled from the sources listed below.

	https://github.com/sparrc/go-ping
	https://stackoverflow.com/questions/2937123/implementing-icmp-ping-in-go/27773040
*/

import (
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/untangle/packetd/services/logger"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

/*
	FIXME - The refreshActivePingInfo function in stats.go currently compiles the interface details.
	It always prefers IPv4, and will flag an interface for IPv6 when that is the only protocol available.
	This would be a problem if an interface has both an IPv4 and IPv6 address configured, but only the
	IPv6 address can reach the internet.
*/

const pingCheckTotal = 3

var pingCheckTargets = [pingCheckTotal]string{"www.google.com", "google-public-dns-a.google.com", "1dot1dot1dot1.cloudflare-dns.com"}
var pingCheckJitter [pingCheckTotal][256]int64

const pingCheckIntervalSec = 5

const (
	protoIGNORE = 0
	protoICMP4  = 1
	protoICMP6  = 58
)

// pingTarget holds the details for an active ping that has been transmitted and is waiting for a reply
type pingTarget struct {
	interfaceID int
	protocol    int
	srcAddress  string
	dstAddress  string
	xmitTime    time.Time
	index       int
}

// pingSocket holds the details of a packet connection that is open and active for sending and receiving pings
type pingSocket struct {
	conn        *net.IPConn
	interfaceID int
	protocol    int
	netAddress  string
}

var socketList map[string]*pingSocket

var masterPid int
var pingMap map[uint16]*pingTarget
var pingLocker sync.Mutex

var sequenceCounter uint16
var sequenceLocker sync.Mutex

func pingerTask() {
	masterPid = os.Getpid() & 0xFFFF
	pingMap = make(map[uint16]*pingTarget)

	// jitter will always be a positive value so we initialize the last value array
	// with minus one so we don't use the first latency we calculate as the jitter
	for x := 0; x < pingCheckTotal; x++ {
		for y := 0; y < 256; y++ {
			pingCheckJitter[x][y] = -1
		}
	}

	openNetworkSockets()

	for {
		select {
		case finish := <-pingerChannel:
			// always close any open sockets
			closeNetworkSockets()

			// always create an empty map for active pings
			pingLocker.Lock()
			pingMap = make(map[uint16]*pingTarget)
			pingLocker.Unlock()

			// true on the channel means time to shutdown
			if finish == true {
				pingerChannel <- true
				return
			}
			// not shutting down so re-open the network sockets to pick up any interface changes
			openNetworkSockets()
		case <-time.After(time.Second * time.Duration(pingCheckIntervalSec)):
			pingerWorker()
		}
	}
}

func pingerWorker() {
	// if we detect interface changes refresh the interface detail and active
	// ping maps and signal our control channel to do a socket refresh
	if checkForInterfaceChanges() {
		logger.Info("Interface changes detected. Recycling ICMP sockets\n")
		loadInterfaceDetailMap()
		refreshActivePingInfo()
		pingerChannel <- false
		return
	}

	// if there are no active ping sockets we can't do active latency checks
	// so refresh the interface and ping maps and do a socket refresh
	if len(socketList) == 0 {
		logger.Info("No active ping interfaces. Recycling ICMP sockets\n")
		loadInterfaceDetailMap()
		refreshActivePingInfo()
		pingerChannel <- false
		return
	}

	// before starting a batch of pings we log a timeout and do cleanup of any previous outstanding
	pingLocker.Lock()
	for index, entry := range pingMap {
		logger.Debug("Detected ping timeout for %s on interface %s\n", entry.dstAddress, entry.srcAddress)
		interfaceMetricLocker.Lock()
		interfaceMetricList[entry.interfaceID].PingTimeout++
		interfaceMetricLocker.Unlock()
		delete(pingMap, index)
	}
	pingLocker.Unlock()

	for srcaddr, socket := range socketList {
		for x := 0; x < len(pingCheckTargets); x++ {
			var target pingTarget
			target.index = x
			target.interfaceID = socket.interfaceID
			target.protocol = socket.protocol
			target.srcAddress = srcaddr
			target.dstAddress = pingCheckTargets[x]
			target.xmitTime = time.Now()
			pingLocker.Lock()
			sequence := pingNetworkAddress(socket, target.protocol, target.srcAddress, target.dstAddress)
			pingMap[sequence] = &target
			pingLocker.Unlock()
		} // end pingCheckTarget loop
	} // end socketList loop
}

func openNetworkSockets() {
	var socket *pingSocket
	var proto string
	var err error

	// make a new list of the sockets we are going to open
	socketList = make(map[string]*pingSocket)

	interfaceDetailLocker.Lock()
	defer interfaceDetailLocker.Unlock()

	for _, item := range interfaceDetailMap {
		switch item.pingMode {
		case protoIGNORE:
			continue
		case protoICMP6:
			proto = "ip6:ipv6-icmp"
		case protoICMP4:
			proto = "ip4:icmp"
		default:
			continue
		}
		socket = new(pingSocket)
		socket.protocol = item.pingMode
		socket.interfaceID = item.interfaceID
		socket.netAddress = item.netAddress
		socket.conn, err = net.ListenIP(proto, &net.IPAddr{IP: net.IPv4zero})
		if err != nil {
			logger.Err("Error %v returned from ListenIP()\n", err)
			continue
		}

		file, err := socket.conn.File()
		if err != nil {
			logger.Err("Error %v returned from socket.conn.File()\n", err)
			continue
		}
		fd := file.Fd()

		err = syscall.BindToDevice(int(fd), item.deviceName)
		if err != nil {
			logger.Err("Error %v returned from syscall.BindToDevice()\n", err)
			syscall.SetNonblock(int(fd), true)
			file.Close()
			continue
		}

		// Calling socket.conn.File() above causes the
		// underlying socket to be switched to blocking
		// so switch it back before closing
		syscall.SetNonblock(int(fd), true)
		file.Close()

		logger.Debug("ICMP listening on INT:%s PROTO:%d\n", item.deviceName, socket.protocol)
		socketList[item.netAddress] = socket
		go watchNetworkSocket(socket)
	}
}

func closeNetworkSockets() {
	for _, socket := range socketList {
		logger.Debug("ICMP disconnecting from ADDR:%s PROTO:%d\n", socket.netAddress, socket.protocol)
		socket.conn.Close()
	}
}

func watchNetworkSocket(socket *pingSocket) {
	var buffer = make([]byte, 1500)
	var target *pingTarget
	var reply *icmp.Message

	for {
		size, peer, err := socket.conn.ReadFrom(buffer)
		logger.Trace("ICMP RECV SIZE:%v PEER:%v ERR:%v\n", size, peer, err)
		if err != nil {
			// we close the net.IPConn to interrupt the blocking ReadFrom on shutdown
			// so we look for and squelch that specific error since it is expected
			if !strings.Contains(err.Error(), "use of closed network connection") {
				logger.Warn("Error %v calling conn.ReadFrom()\n", err)
			}
			return
		}

		reply, err = icmp.ParseMessage(socket.protocol, buffer[:size])
		if err != nil {
			logger.Warn("Error %v returned from icmp.ParseMessage\n", err)
			continue
		}

		// if we are handling ICMP4 and reply is not ICMP4 just ignore
		if (socket.protocol == protoICMP4) && (reply.Type != ipv4.ICMPTypeEchoReply) {
			continue
		}

		// if we are handing ICMP6 and reply is not ICMP6 just ignore
		if (socket.protocol == protoICMP6) && (reply.Type != ipv6.ICMPTypeEchoReply) {
			continue
		}

		// make sure the ID in the reply matches our PID from the request
		answer := reply.Body.(*icmp.Echo)
		if answer.ID != masterPid {
			continue
		}

		// looks like a reply for us so use the sequence number to find and remove the outstanding target in the map
		index := uint16(answer.Seq)
		pingLocker.Lock()
		target = pingMap[index]
		delete(pingMap, index)
		pingLocker.Unlock()

		// if we didn't find an active target waiting for this reply just log a warning
		if target == nil {
			logger.Warn("No map entry found for ping reply:%d\n", answer.Seq)
			continue
		}

		// active target found so compute the latency and add to the active and collective stats collectors
		duration := time.Since(target.xmitTime)

		statsLocker[target.interfaceID].Lock()
		statsCollector[target.interfaceID].AddDataPoint(float64(duration.Nanoseconds()) / 1000000.0)
		statsLocker[target.interfaceID].Unlock()

		activeLocker[target.interfaceID].Lock()
		activeCollector[target.interfaceID].AddDataPoint(float64(duration.Nanoseconds()) / 1000000.0)
		activeLocker[target.interfaceID].Unlock()

		// if we don't have the previous latency for this [target][interface] store and continue
		if pingCheckJitter[target.index][target.interfaceID] < 0 {
			pingCheckJitter[target.index][target.interfaceID] = duration.Nanoseconds()
			continue
		}

		// we have the previous latency so we can calculate the jitter
		var jitter int64

		if duration.Nanoseconds() > pingCheckJitter[target.index][target.interfaceID] {
			jitter = (duration.Nanoseconds() - pingCheckJitter[target.index][target.interfaceID])
		} else {
			jitter = (pingCheckJitter[target.index][target.interfaceID] - duration.Nanoseconds())
		}

		pingCheckJitter[target.index][target.interfaceID] = duration.Nanoseconds()

		jitterLocker[target.interfaceID].Lock()
		jitterCollector[target.interfaceID].AddDataPoint(float64(jitter) / 1000000.0)
		jitterLocker[target.interfaceID].Unlock()
	}
}

func pingNetworkAddress(socket *pingSocket, protocol int, srcAddress string, dstAddress string) uint16 {
	var netaddr *net.IPAddr
	var mess icmp.Message
	var size int
	var err error

	if protocol == protoICMP6 {
		netaddr, err = net.ResolveIPAddr("ip6", dstAddress)
	} else {
		netaddr, err = net.ResolveIPAddr("ip4", dstAddress)
	}

	if err != nil {
		return 0
	}

	ourseq := nextSequenceNumber()

	mess.Code = 0
	mess.Body = &icmp.Echo{
		ID:   masterPid,
		Seq:  int(ourseq),
		Data: []byte("MicroFirewall Network Latency Probe"),
	}

	if protocol == protoICMP6 {
		mess.Type = ipv6.ICMPTypeEchoRequest
	} else {
		mess.Type = ipv4.ICMPTypeEcho
	}

	data, err := mess.Marshal(nil)
	if err != nil {
		return 0
	}

	size, err = socket.conn.WriteToIP(data, &net.IPAddr{IP: netaddr.IP})
	logger.Trace("ICMP XMIT SIZE:%v PEER:%v ERR:%v\n", size, netaddr, err)

	if err != nil {
		return 0
	}

	return ourseq
}

func nextSequenceNumber() uint16 {
	sequenceLocker.Lock()
	defer sequenceLocker.Unlock()
	sequenceCounter++
	if sequenceCounter == 0 {
		sequenceCounter = 1
	}
	return sequenceCounter
}
