package kernel

/*
#include "common.h"
#cgo CFLAGS: -D_GNU_SOURCE
#cgo LDFLAGS: -lnetfilter_queue -lnfnetlink -lnetfilter_conntrack -lnetfilter_log
*/
import "C"

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/untangle/packetd/services/logger"
	"net"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// ConntrackCallback is a function to handle conntrack events
type ConntrackCallback func(uint32, uint8, uint8, uint8, net.IP, net.IP, uint16, uint16, net.IP, net.IP, uint16, uint16, uint64, uint64)

// NfqueueCallback is a function to handle nfqueue events
type NfqueueCallback func(uint32, gopacket.Packet, int, uint32) (int, uint32)

// NetloggerCallback is a function to handle netlogger events
type NetloggerCallback func(uint8, uint8, uint16, uint8, uint8, string, string, uint16, uint16, uint32, string)

// To give C child functions access we export go_child_startup and shutdown functions.
var childsync sync.WaitGroup
var shutdownConntrackTask = make(chan bool)
var conntrackCallback ConntrackCallback
var nfqueueCallback NfqueueCallback
var netloggerCallback NetloggerCallback
var debugFlag bool

// Startup starts kernel services
func Startup() {
}

// Shutdown stops kernel services
func Shutdown() {
}

// StartCallbacks donates threads for all the C services and starts other persistent tasks
func StartCallbacks() {
	// Donate threads to kernel hooks
	go C.nfqueue_thread()
	go C.conntrack_thread()
	go C.netlogger_thread()

	// start the conntrack 60-second update task
	go conntrackTask()
}

// StopCallbacks stops all C services and callbacks
func StopCallbacks() {
	// make sure the shutdown flag is set
	SetShutdownFlag()

	// Send shutdown signal to periodicTask and wait for it to return
	// wait on above shutdowns
	c := make(chan bool)
	go func() {
		shutdownConntrackTask <- true
		childsync.Wait()
		c <- true
	}()

	select {
	case <-c:
	case <-time.After(10 * time.Second):
		logger.Err("Failed to properly shutdown conntrackPeriodicTask\n")
		// print stack trace
		syscall.Kill(syscall.Getpid(), syscall.SIGQUIT)
		time.Sleep(1 * time.Second)
	}
}

// GetShutdownFlag returns the C shutdown flag
func GetShutdownFlag() int {
	return int(C.get_shutdown_flag())
}

// SetShutdownFlag sets the C shutdown flag
func SetShutdownFlag() {
	C.set_shutdown_flag(1)
}

// GetDebugFlag gets the shared debug flag
func GetDebugFlag() bool {
	return debugFlag
}

// SetDebugFlag sets the shared debug flag
func SetDebugFlag() {
	debugFlag = true
}

// GetBypassFlag gets the live traffic bypass flag
func GetBypassFlag() int {
	return int(C.get_bypass_flag())
}

// SetBypassFlag flag sets the live traffic bypass flag
func SetBypassFlag(value int) {
	C.set_bypass_flag(C.int(value))
}

// GetWarehouseFlag gets the value of the warehouse traffic capture and playback flag
func GetWarehouseFlag() int {
	return int(C.get_warehouse_flag())
}

// SetWarehouseFlag sets the value of the warehouse traffic capture and playback flag
func SetWarehouseFlag(value int) {
	C.set_warehouse_flag(C.int(value))
}

// SetWarehouseSpeed sets the traffic playback speed
func SetWarehouseSpeed(value int) {
	C.set_warehouse_speed(C.int(value))
}

// SetWarehouseFile sets the filename used by the warehouse for traffic capture and playback
func SetWarehouseFile(filename string) {
	C.set_warehouse_file(C.CString(filename))
}

// StartWarehouseCapture initializes the warehouse traffic capture function
func StartWarehouseCapture() {
	C.start_warehouse_capture()
}

// CloseWarehouseCapture closes the warehouse traffic capture function
func CloseWarehouseCapture() {
	C.close_warehouse_capture()
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
func go_nfqueue_callback(mark C.uint32_t, data *C.uchar, size C.int, ctid C.uint32_t, nfid C.uint32_t, buffer *C.char) {
	if nfqueueCallback == nil {
		logger.Warn("No queue callback registered. Ignoring packet.\n")
		C.nfqueue_set_verdict(nfid, C.NF_ACCEPT, mark)
		C.nfqueue_free_buffer(buffer)
		return
	}

	go func(mark C.uint32_t, data *C.uchar, size C.int, ctid C.uint32_t, nfid C.uint32_t, buffer *C.char) {

		var packet gopacket.Packet
		var packetLength int
		var conntrackID uint32 = uint32(C.int(ctid))
		var pmark uint32 = uint32(C.int(mark))

		// create a Go pointer and gopacket from the packet data
		pointer := (*[0xFFFF]byte)(unsafe.Pointer(data))[:int(size):int(size)]

		if pointer[0]&0xF0 == 0x40 {
			packet = gopacket.NewPacket(pointer, layers.LayerTypeIPv4, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
		} else {
			packet = gopacket.NewPacket(pointer, layers.LayerTypeIPv6, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
		}

		packetLength = int(size)

		verdict, newMark := nfqueueCallback(conntrackID, packet, packetLength, pmark)
		C.nfqueue_set_verdict(nfid, C.uint32_t(verdict), C.uint32_t(newMark))
		C.nfqueue_free_buffer(buffer)

	}(mark, data, size, ctid, nfid, buffer)

	return
}

//export go_conntrack_callback
func go_conntrack_callback(info *C.struct_conntrack_info) {
	var ctid uint32
	var family uint8
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
		logger.Warn("No conntrack callback registered. Ignoring event.\n")
		return
	}

	ctid = uint32(info.conn_id)
	family = uint8(info.family)
	eventType = uint8(info.msg_type)
	c2sBytes = uint64(info.orig_bytes)
	s2cBytes = uint64(info.repl_bytes)
	protocol = uint8(info.orig_proto)

	if family == C.AF_INET {
		client = make(net.IP, 4)
		server = make(net.IP, 4)
		clientNew = make(net.IP, 4)
		serverNew = make(net.IP, 4)

		origSptr := *(*[4]byte)(unsafe.Pointer(&info.orig_saddr))
		origDptr := *(*[4]byte)(unsafe.Pointer(&info.orig_daddr))
		replSptr := *(*[4]byte)(unsafe.Pointer(&info.repl_saddr))
		replDptr := *(*[4]byte)(unsafe.Pointer(&info.repl_daddr))

		copy(client, origSptr[:])
		copy(server, origDptr[:])
		copy(clientNew, replDptr[:])
		copy(serverNew, replSptr[:])
	}

	if family == C.AF_INET6 {
		client = make(net.IP, 16)
		server = make(net.IP, 16)
		clientNew = make(net.IP, 16)
		serverNew = make(net.IP, 16)

		origSptr := *(*[16]byte)(unsafe.Pointer(&info.orig_saddr))
		origDptr := *(*[16]byte)(unsafe.Pointer(&info.orig_daddr))
		replSptr := *(*[16]byte)(unsafe.Pointer(&info.repl_saddr))
		replDptr := *(*[16]byte)(unsafe.Pointer(&info.repl_daddr))

		copy(client, origSptr[:])
		copy(server, origDptr[:])
		copy(clientNew, replDptr[:])
		copy(serverNew, replSptr[:])
	}

	clientPort = uint16(info.orig_sport)
	serverPort = uint16(info.orig_dport)
	clientPortNew = uint16(info.repl_dport)
	serverPortNew = uint16(info.repl_sport)

	conntrackCallback(ctid, family, eventType, protocol,
		client, server, clientPort, serverPort,
		clientNew, serverNew, clientPortNew, serverPortNew,
		c2sBytes, s2cBytes)
}

//export go_netlogger_callback
func go_netlogger_callback(info *C.struct_netlogger_info) {
	var version uint8 = uint8(info.version)
	var protocol uint8 = uint8(info.protocol)
	var icmpType uint16 = uint16(info.icmp_type)
	var srcInterface uint8 = uint8(info.src_intf)
	var dstInterface uint8 = uint8(info.dst_intf)
	var srcAddress string = C.GoString(&info.src_addr[0])
	var dstAddress string = C.GoString(&info.dst_addr[0])
	var srcPort uint16 = uint16(info.src_port)
	var dstPort uint16 = uint16(info.dst_port)
	var mark uint32 = uint32(info.mark)
	var prefix string = C.GoString(&info.prefix[0])

	if netloggerCallback == nil {
		logger.Warn("No conntrack callback registered. Ignoring event.\n")
		return
	}

	netloggerCallback(version, protocol, icmpType, srcInterface, dstInterface, srcAddress, dstAddress, srcPort, dstPort, mark, prefix)
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
	logger.LogMessageSource(int(level), lsrc, lmsg)
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
			logger.Debug("Calling conntrack dump %d\n", counter)
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

// UpdateConntrackMark updates the conntrack entry specified by ctid
// by anding it with mask and oring it with value
func UpdateConntrackMark(ctid uint32, mask uint32, value uint32) {
	C.conntrack_update_mark(C.uint32_t(ctid), C.uint32_t(mask), C.uint32_t(value))
}

// PlaybackWarehouseFile plays back a warehouse capture file
func PlaybackWarehouseFile() {
	go func() {
		C.warehouse_playback()
	}()
}
