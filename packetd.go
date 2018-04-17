package main

//#include "common.h"
//#include "netfilter.h"
//#include "conntrack.h"
//#include "netlogger.h"
//#cgo LDFLAGS: -lnetfilter_queue -lnfnetlink -lnetfilter_conntrack -lnetfilter_log
import "C"

import "os"
import "time"
import "sync"
import "bufio"
import "unsafe"
import "github.com/untangle/packetd/support"
import "github.com/untangle/packetd/example"
import "github.com/untangle/packetd/classify"
import "github.com/untangle/packetd/geoip"
import "github.com/untangle/packetd/restd"

/*---------------------------------------------------------------------------*/

/*
 * The childsync is used to give the main process something to watch while
 * waiting for all of the goroutine children to finish execution and cleanup.
 * To give C child functions access we export go_child_startup and goodbye
 * functions. For children in normal go packages, we pass the WaitGroup
 * directly to the goroutine.
 */
var childsync sync.WaitGroup

/*---------------------------------------------------------------------------*/
func main() {
	var lastmin int
	var counter int

	support.Startup()
	C.common_startup()

	support.LogMessage("Untangle Packet Daemon Version %s\n", "1.00")

	go C.netfilter_thread()
	go C.conntrack_thread()
	go C.netlogger_thread()

	// ********** Call all plugin startup functions here

	go example.Plugin_Startup(&childsync)
	go classify.Plugin_Startup(&childsync)
	go geoip.Plugin_Startup(&childsync)

	// ********** End of plugin startup functions

	ch := make(chan string)
	go func(ch chan string) {
		reader := bufio.NewReader(os.Stdin)
		for {
			s, err := reader.ReadString('\n')
			if err != nil {
				close(ch)
				return
			}
			ch <- s
		}
		close(ch)
	}(ch)

	// Start REST HTTP daemon
	go restd.StartRestDaemon()

	support.LogMessage("RUNNING ON CONSOLE - HIT ENTER TO EXIT\n")

stdinloop:
	for {
		shutdown := C.get_shutdown_flag()
		if shutdown != 0 {
			break
		}
		select {
		case stdin, ok := <-ch:
			if !ok {
				break stdinloop
			} else {
				support.LogMessage("Console input detected - Application shutting down\n")
				_ = stdin
				break stdinloop
			}
		case <-time.After(1 * time.Second):
			current := time.Now()
			if current.Minute() != lastmin {
				lastmin = current.Minute()
				counter++
				support.LogMessage("Calling perodic conntrack dump %d\n", counter)
				C.conntrack_dump()
			}
		}
	}

	// ********** Call all plugin goodbye functions here

	go example.Plugin_Goodbye(&childsync)
	go classify.Plugin_Goodbye(&childsync)
	go geoip.Plugin_Goodbye(&childsync)

	// ********** End of plugin goodbye functions

	C.netfilter_goodbye()
	C.conntrack_goodbye()
	C.netlogger_goodbye()
	childsync.Wait()
}

/*---------------------------------------------------------------------------*/
//export go_netfilter_callback
func go_netfilter_callback(mark C.int, data *C.uchar, size C.int) int32 {

	// this version creates a Go copy of the buffer
	// buffer := C.GoBytes(unsafe.Pointer(data),size)

	// this version creates a Go pointer to the buffer
	buffer := (*[0xFFFF]byte)(unsafe.Pointer(data))[:int(size):int(size)]
	length := int(size)

	// ********** Call all plugin netfilter handler functions here

	c1 := make(chan int32)
	go example.Plugin_netfilter_handler(c1, buffer, length)
	c2 := make(chan int32)
	go classify.Plugin_netfilter_handler(c2, buffer, length)
	c3 := make(chan int32)
	go geoip.Plugin_netfilter_handler(c3, buffer, length)

	// ********** End of plugin netfilter callback functions

	// get the existing mark on the packet
	var pmark int32 = int32(C.int(mark))

	// add the mark bits returned from each package handler
	for i := 0; i < 2; i++ {
		select {
		case mark1 := <-c1:
			pmark |= mark1
		case mark2 := <-c2:
			pmark |= mark2
		case mark3 := <-c3:
			pmark |= mark3
		}
	}

	// return the updated mark to be set on the packet
	return (pmark)
}

/*---------------------------------------------------------------------------*/
//export go_conntrack_callback
func go_conntrack_callback(info *C.struct_conntrack_info) {
	var tracker support.Tracker

	tracker.Orig_src_addr = uint32(info.orig_saddr)
	tracker.Repl_src_addr = uint32(info.repl_saddr)
	tracker.Orig_dst_addr = uint32(info.orig_daddr)
	tracker.Repl_dst_addr = uint32(info.repl_daddr)
	tracker.Orig_src_port = uint16(info.orig_sport)
	tracker.Repl_src_port = uint16(info.repl_sport)
	tracker.Orig_dst_port = uint16(info.orig_dport)
	tracker.Repl_dst_port = uint16(info.repl_dport)
	tracker.Orig_protocol = uint8(info.orig_proto)
	tracker.Repl_protocol = uint8(info.repl_proto)

	// ********** Call all plugin conntrack handler functions here

	go example.Plugin_conntrack_handler(&tracker)

	// ********** End of plugin netfilter callback functions

}

/*---------------------------------------------------------------------------*/
//export go_netlogger_callback
func go_netlogger_callback(info *C.struct_netlogger_info) {
	var logger support.Logger

	logger.Protocol = uint8(info.protocol)
	logger.IcmpType = uint16(info.icmp_type)
	logger.SrcIntf = uint8(info.src_intf)
	logger.DstIntf = uint8(info.dst_intf)
	logger.SrcAddr = uint32(info.src_addr)
	logger.DstAddr = uint32(info.dst_addr)
	logger.SrcPort = uint16(info.src_port)
	logger.DstPort = uint16(info.dst_port)
	logger.Mark = uint32(info.mark)
	logger.Prefix = C.GoString(info.prefix)

	// ********** Call all plugin netlogger handler functions here

	go example.Plugin_netlogger_handler(&logger)

	// ********** End of plugin netlogger callback functions
}

/*---------------------------------------------------------------------------*/
//export go_child_startup
func go_child_startup() {
	childsync.Add(1)
}

/*---------------------------------------------------------------------------*/
//export go_child_goodbye
func go_child_goodbye() {
	childsync.Done()
}

/*---------------------------------------------------------------------------*/
