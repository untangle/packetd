package kernel

/*
#include "common.h"
#cgo CFLAGS: -D_GNU_SOURCE
#cgo LDFLAGS: -lnetfilter_queue -lnfnetlink -lnetfilter_conntrack -lnetfilter_log -lnftnl -lmnl
*/
import "C"

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/untangle/packetd/services/logger"
)

// ConntrackCallback is a function to handle conntrack events
type ConntrackCallback func(uint32, uint32, uint8, uint8, uint8, net.IP, net.IP, uint16, uint16, net.IP, net.IP, uint16, uint16, uint64, uint64, uint64, uint64, uint64, uint64, uint32, uint8)

// NfqueueCallback is a function to handle nfqueue events
type NfqueueCallback func(uint32, uint32, gopacket.Packet, int, uint32) int

// NetloggerCallback is a function to handle netlogger events
type NetloggerCallback func(uint8, uint8, uint16, uint8, uint8, string, string, uint16, uint16, uint32, uint32, string)

// To give C child functions access we export go_child_startup and shutdown functions which
var childsync sync.WaitGroup
var shutdownConntrackTask = make(chan bool)
var conntrackCallback ConntrackCallback
var nfqueueCallback NfqueueCallback
var netloggerCallback NetloggerCallback
var shutdownFlag uint32
var shutdownChannel = make(chan bool)
var shutdownChannelCloseOnce sync.Once

// FlagNoNfqueue can be set to disable the nfqueue callback
var FlagNoNfqueue bool

// FlagNoConntrack can be set to disable the conntrack callback
var FlagNoConntrack bool

// FlagNoNetlogger can be set to disable the netlogger callback
var FlagNoNetlogger bool

// FlagNoCloud can be set to disable all cloud services
var FlagNoCloud bool

// These maps are used to track ctid's we see during playback. They are set to the
// maps passed to the playback function and cleared when playback is finished.
var nfCleanTracker map[uint32]bool
var ctCleanTracker map[uint32]bool

// Startup starts kernel services
func Startup() {
}

// Shutdown stops kernel services
func Shutdown() {
}

// StartCallbacks donates threads for all the C services and starts other persistent tasks
func StartCallbacks(numNfqueueThreads int, intervalSeconds int) {
	// Donate threads to kernel hooks
	if numNfqueueThreads > 32 {
		numNfqueueThreads = 32
	}

	if FlagNoNfqueue == false {
		for x := 0; x < numNfqueueThreads; x++ {
			go func(x C.int) {
				//runtime.LockOSThread()
				C.nfqueue_thread(x)
			}(C.int(x))
		}
	} else {
		logger.Warn("***** ATTENTION! ***** The no-nfqueue flag is set - Not installing nfqueue callback\n")
	}

	if FlagNoConntrack == false {
		go func() {
			//runtime.LockOSThread()
			C.conntrack_thread()
		}()

		// start the conntrack interval-second update task
		go func() {
			//runtime.LockOSThread()
			conntrackTask(intervalSeconds)
		}()

	} else {
		logger.Warn("***** ATTENTION! ***** The no-conntrack flag is set - Not installing conntrack callback\n")
	}

	if FlagNoNetlogger == false {
		go func() {
			//runtime.LockOSThread()
			C.netlogger_thread()
		}()
	} else {
		logger.Warn("***** ATTENTION! ***** The no-netlogger flag is set - Not installing netlogger callback\n")
	}
}

// StopCallbacks stops all C services and callbacks
func StopCallbacks() {
	c := make(chan bool)

	// make sure the shutdown flag is set
	SetShutdownFlag()

	if FlagNoConntrack == false {
		// send shutdown signal to periodicTask and wait for it to return
		go func() {
			shutdownConntrackTask <- true
			c <- true
		}()

		select {
		case <-c:
			logger.Info("Successful shutdown of conntrackTask\n")
		case <-time.After(10 * time.Second):
			logger.Err("Failed to properly shutdown conntrackPeriodicTask\n")
		}
	}

	// wait for everything else to finish
	go func() {
		childsync.Wait()
		c <- true
	}()

	select {
	case <-c:
	case <-time.After(10 * time.Second):
		logger.Err("Timeout waiting for childsync WaitGroup\n")
	}
}

// GetShutdownFlag returns the shutdown flag for kernel
func GetShutdownFlag() bool {
	if atomic.LoadUint32(&shutdownFlag) != 0 {
		return true
	}
	return false
}

// SetShutdownFlag sets the shutdown flag for kernel
func SetShutdownFlag() {
	atomic.StoreUint32(&shutdownFlag, 1)
	shutdownChannelCloseOnce.Do(func() {
		close(shutdownChannel)
	})
}

// GetShutdownChannel returns a channel
func GetShutdownChannel() chan bool {
	return shutdownChannel
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

//export go_get_shutdown_flag
func go_get_shutdown_flag() int32 {
	if atomic.LoadUint32(&shutdownFlag) != 0 {
		return 1
	}
	return 0
}

//export go_set_shutdown_flag
func go_set_shutdown_flag() {
	SetShutdownFlag()
}

//export go_nfqueue_callback
func go_nfqueue_callback(mark C.uint32_t, data *C.uchar, size C.int, ctid C.uint32_t, nfid C.uint32_t, family C.uint32_t, buffer *C.char, playflag C.int, index C.int) {
	if nfqueueCallback == nil {
		logger.Warn("No queue callback registered. Ignoring packet.\n")
		C.nfqueue_set_verdict(index, nfid, C.NF_ACCEPT)
		C.nfqueue_free_buffer(buffer)
		return
	}

	// if the playback flag is set add the ctid to our cleanup list
	if playflag != 0 && nfCleanTracker != nil {
		nfCleanTracker[uint32(C.int(ctid))] = true
	}

	f := func(mark C.uint32_t, data *C.uchar, size C.int, ctid C.uint32_t, nfid C.uint32_t, family C.uint32_t, buffer *C.char) {

		var packet gopacket.Packet
		var packetLength int
		var conntrackID uint32 = uint32(C.int(ctid))
		var pmark uint32 = uint32(C.int(mark))
		var fam uint32 = uint32(C.int(family))

		// create a Go pointer and gopacket from the packet data
		pointer := (*[0xFFFF]byte)(unsafe.Pointer(data))[:int(size):int(size)]

		if pointer[0]&0xF0 == 0x40 {
			packet = gopacket.NewPacket(pointer, layers.LayerTypeIPv4, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
		} else {
			packet = gopacket.NewPacket(pointer, layers.LayerTypeIPv6, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
		}

		packetLength = int(size)

		verdict := nfqueueCallback(conntrackID, fam, packet, packetLength, pmark)
		if playflag == 0 {
			C.nfqueue_set_verdict(index, nfid, C.uint32_t(verdict))
		}
		C.nfqueue_free_buffer(buffer)

	}

	// if playflag != 0 then we are doing a warehouse recording playback
	// in this case we often speed up these playbacks, and as such
	// if we launch this asynchronously and return the next packet will
	// immediately be handled. This means we essentially handle all packets
	// simultaneously which means the plugins will get all the packets
	// out of order depending on the scheduler. If in a playback
	// call synchronously to ensure the packets come in the correct order

	// if this is not a playback, handle this packet is a goroutine
	// and return the main thread immediately so it can handle more packets
	if playflag != 0 {
		f(mark, data, size, ctid, nfid, family, buffer)
	} else {
		go f(mark, data, size, ctid, nfid, family, buffer)
	}

	return
}

//export go_conntrack_callback
func go_conntrack_callback(info *C.struct_conntrack_info, playflag C.int) {
	var ctid uint32
	var family uint8
	var eventType uint8
	var c2sBytes uint64
	var s2cBytes uint64
	var c2sPackets uint64
	var s2cPackets uint64
	var protocol uint8
	var client net.IP
	var server net.IP
	var clientPort uint16
	var serverPort uint16
	var clientNew net.IP
	var serverNew net.IP
	var clientPortNew uint16
	var serverPortNew uint16
	var connmark uint32
	var tcpState uint8
	var timestampStart uint64
	var timestampStop uint64
	var timeout uint32

	if conntrackCallback == nil {
		logger.Warn("No conntrack callback registered. Ignoring event.\n")
		return
	}

	ctid = uint32(info.conn_id)

	// if the playback flag is set add the ctid to our cleanup list
	if playflag != 0 && ctCleanTracker != nil {
		ctCleanTracker[ctid] = true
	}

	family = uint8(info.family)
	eventType = uint8(info.msg_type)
	c2sBytes = uint64(info.orig_bytes)
	s2cBytes = uint64(info.repl_bytes)
	c2sPackets = uint64(info.orig_packets)
	s2cPackets = uint64(info.repl_packets)

	protocol = uint8(info.orig_proto)
	connmark = uint32(info.conn_mark)
	tcpState = uint8(info.tcp_state)
	timestampStart = uint64(info.timestamp_start)
	timestampStop = uint64(info.timestamp_stop)
	timeout = uint32(info.timeout)

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

	conntrackCallback(ctid, connmark, family, eventType, protocol,
		client, server, clientPort, serverPort,
		clientNew, serverNew, clientPortNew, serverPortNew,
		c2sBytes, s2cBytes, c2sPackets, s2cPackets, timestampStart, timestampStop, timeout, tcpState)
}

//export go_netlogger_callback
func go_netlogger_callback(info *C.struct_netlogger_info, playflag C.int) {
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
	var ctid uint32 = uint32(info.ctid)
	var prefix string = C.GoString(&info.prefix[0])

	if netloggerCallback == nil {
		logger.Warn("No conntrack callback registered. Ignoring event.\n")
		return
	}

	netloggerCallback(version, protocol, icmpType, srcInterface, dstInterface, srcAddress, dstAddress, srcPort, dstPort, mark, ctid, prefix)
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
	logger.LogMessageSource(int32(level), lsrc, lmsg)
}

//conntrack periodic task
func conntrackTask(intervalSeconds int) {
	var counter int

	for {
		select {
		case <-shutdownConntrackTask:
			return
		case <-time.After(time.Second * time.Duration(intervalSeconds)):
			//case <-time.After(timeUntilNextMin()):
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

// WarehousePlaybackFile plays a warehouse capture file and returns the list of netfilter
// conntrack sessions that were detected so the caller can clean them up
func WarehousePlaybackFile(nflist map[uint32]bool, ctlist map[uint32]bool) {
	nfCleanTracker = nflist
	ctCleanTracker = ctlist
	C.warehouse_playback()
	nfCleanTracker = nil
	ctCleanTracker = nil
}

func BypassViaNftSet(ctid uint32, timeout uint64) {
	C.bypass_via_nft_set(C.uint32_t(ctid), C.uint64_t(timeout))
}
