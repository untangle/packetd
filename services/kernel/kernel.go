package kernel

/*
#include "common.h"
#cgo CFLAGS: -D_GNU_SOURCE
#cgo LDFLAGS: -lnetfilter_queue -lnfnetlink -lnetfilter_conntrack -lnetfilter_log
*/
import "C"

import (
	"encoding/binary"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/untangle/packetd/services/logger"
	"net"
	"sync"
	"time"
	"unsafe"
)

// ConntrackCallback is a function to handle conntrack events
type ConntrackCallback func(uint32, uint8, uint8, net.IP, net.IP, uint16, uint16, net.IP, net.IP, uint16, uint16, uint64, uint64)

// NfqueueCallback is a function to handle nfqueue events
type NfqueueCallback func(uint32, gopacket.Packet, int, uint32) uint32

// NetloggerCallback is a function to handle netlogger events
type NetloggerCallback func(uint8, uint8, uint16, uint8, uint8, string, string, uint16, uint16, uint32, string)

// To give C child functions access we export go_child_startup and shutdown functions.
var childsync sync.WaitGroup
var logsrc = "kernel"
var shutdownConntrackTask = make(chan bool)
var conntrackCallback ConntrackCallback
var nfqueueCallback NfqueueCallback
var netloggerCallback NetloggerCallback

// Startup starts C services
func Startup() {
	C.common_startup()
}

// StartCallbacks donates threads for all the C services
// after this all callbacks will be called using these threads
func StartCallbacks() {
	// Donate threads to kernel hooks
	go C.nfqueue_thread()
	go C.conntrack_thread()
	go C.netlogger_thread()

	// start the conntrack 60-second update task
	go conntrackTask()
}

// StopCallbacks stops all services and callbacks
func StopCallbacks() {
	// Remove all kernel hooks
	go C.nfqueue_shutdown()
	go C.conntrack_shutdown()
	go C.netlogger_shutdown()

	// Send shutdown signal to periodicTask and wait for it to return
	shutdownConntrackTask <- true
	select {
	case <-shutdownConntrackTask:
	case <-time.After(10 * time.Second):
		logger.LogMessage(logger.LogErr, logsrc, "Failed to properly shutdown conntrackPeriodicTask\n")
	}

	// wait on above shutdowns
	childsync.Wait()
}

// Shutdown all C services
func Shutdown() {
	C.common_shutdown()
}

// GetShutdownFlag returns the c shutdown flag
func GetShutdownFlag() int {
	return int(C.get_shutdown_flag())
}

// RegisterConntrackCallback registers the global conntrack callback for handling conntrack events
func RegisterConntrackCallback(cb ConntrackCallback) {
	conntrackCallback = cb
}

// RegisterNfqueueCallback registers the global nfqueue callback for handling nfqueue events
func RegisterNfqueueCallback(cb NfqueueCallback) {
	nfqueueCallback = cb
}

// RegisterNetloggerCallback registers the global netlogger callback for handling netlogger events
func RegisterNetloggerCallback(cb NetloggerCallback) {
	netloggerCallback = cb
}

//export go_nfqueue_callback
func go_nfqueue_callback(mark C.uint32_t, data *C.uchar, size C.int, ctid C.uint32_t, nfid C.uint32_t) {
	if nfqueueCallback == nil {
		logger.LogMessage(logger.LogWarn, logsrc, "No queue callback registered. Ignoring packet.\n")
		C.nfqueue_set_verdict(nfid, C.NF_ACCEPT, mark)
		return
	}

	// netfilter queue is a share queue so we cant launch this async without copying contents out of buffer
	// XXX

	// go func(mark C.uint32_t, data *C.uchar, size C.int, ctid C.uint32_t, nfid C.uint32_t) {

	var packet gopacket.Packet
	var packetLength int
	var conntrackID uint32 = uint32(C.int(ctid))
	var pmark uint32 = uint32(C.int(mark))

	buffer := (*[0xFFFF]byte)(unsafe.Pointer(data))[:int(size):int(size)]
	packet = gopacket.NewPacket(buffer, layers.LayerTypeIPv4, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	packetLength = int(size)

	newMark := nfqueueCallback(conntrackID, packet, packetLength, pmark)
	C.nfqueue_set_verdict(nfid, C.NF_ACCEPT, C.uint32_t(newMark))

	// }(mark, data, size, ctid, nfid)

	return
}

//export go_conntrack_callback
func go_conntrack_callback(info *C.struct_conntrack_info) {
	var ctid uint32
	var eventType uint8
	var c2sBytes uint64
	var s2cBytes uint64
	var protocol uint8
	var client net.IP
	var server net.IP
	var clientPort uint16
	var serverPort uint16
	var clientNew net.IP
	var serverNew net.IP
	var clientPortNew uint16
	var serverPortNew uint16

	if conntrackCallback == nil {
		logger.LogMessage(logger.LogWarn, logsrc, "No conntrack callback registered. Ignoring event.\n")
		return
	}

	ctid = uint32(info.conn_id)
	eventType = uint8(info.msg_type)
	c2sBytes = uint64(info.orig_bytes)
	s2cBytes = uint64(info.repl_bytes)

	protocol = uint8(info.orig_proto)

	client = make(net.IP, 4) // FIXME IPv6
	server = make(net.IP, 4) // FIXME IPv6
	binary.LittleEndian.PutUint32(client, uint32(info.orig_saddr))
	binary.LittleEndian.PutUint32(server, uint32(info.orig_daddr))

	clientNew = make(net.IP, 4) // FIXME IPv6
	serverNew = make(net.IP, 4) // FIXME IPv6
	binary.LittleEndian.PutUint32(clientNew, uint32(info.repl_daddr))
	binary.LittleEndian.PutUint32(serverNew, uint32(info.repl_saddr))

	clientPort = uint16(info.orig_sport)
	serverPort = uint16(info.orig_dport)
	clientPortNew = uint16(info.repl_dport)
	serverPortNew = uint16(info.repl_sport)

	conntrackCallback(ctid, eventType, protocol,
		client, server, clientPort, serverPort,
		clientNew, serverNew, clientPortNew, serverPortNew,
		c2sBytes, s2cBytes)
}

//export go_netlogger_callback
func go_netlogger_callback(info *C.struct_netlogger_info) {
	var version uint8 = uint8(info.version)
	var protocol uint8 = uint8(info.protocol)
	var icmpType uint16 = uint16(info.icmp_type)
	var srcIntf uint8 = uint8(info.src_intf)
	var dstIntf uint8 = uint8(info.dst_intf)
	var srcAddr string = C.GoString(&info.src_addr[0])
	var dstAddr string = C.GoString(&info.dst_addr[0])
	var srcPort uint16 = uint16(info.src_port)
	var dstPort uint16 = uint16(info.dst_port)
	var mark uint32 = uint32(info.mark)
	var prefix string = C.GoString(&info.prefix[0])

	if netloggerCallback == nil {
		logger.LogMessage(logger.LogWarn, logsrc, "No conntrack callback registered. Ignoring event.\n")
		return
	}

	netloggerCallback(version, protocol, icmpType, srcIntf, dstIntf, srcAddr, dstAddr, srcPort, dstPort, mark, prefix)
}

//export go_child_startup
func go_child_startup() {
	childsync.Add(1)
}

//export go_child_shutdown
func go_child_shutdown() {
	childsync.Done()
}

//export go_child_message
func go_child_message(level C.int, source *C.char, message *C.char) {
	lsrc := C.GoString(source)
	lmsg := C.GoString(message)
	logger.LogMessage(int(level), lsrc, lmsg)
}

//conntrack periodic task
func conntrackTask() {
	var counter int

	for {
		select {
		case <-shutdownConntrackTask:
			shutdownConntrackTask <- true
			return
		case <-time.After(timeUntilNextMin()):
			counter++
			logger.LogMessage(logger.LogDebug, logsrc, "Calling conntrack dump %d\n", counter)
			C.conntrack_dump()
		}
	}
}

// timeUntilNextMin provides the exact duration until the start of the next minute
func timeUntilNextMin() time.Duration {
	t := time.Now()
	var secondsToWait = 59 - t.Second()
	var millisecondsToWait = 1000 - (t.Nanosecond() / 1000000)
	var duration = (time.Duration(secondsToWait) * time.Second) + (time.Duration(millisecondsToWait) * time.Millisecond)

	return duration
}
