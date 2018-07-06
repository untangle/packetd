// Package dispatch provides dispatching of network/kernel events to various subscribers
// It provides an API for plugins to subscribe to for 3 types of network events
// 1) NFqueue (netfilter queue) packets
// 2) Conntrack events (New, Update, Destroy)
// 3) Netlogger events (from NFLOG target)
// The dispatch will register global callbacks with the kernel package
// and then dispatch events to subscribers accordingly
package dispatch

import (
	"github.com/untangle/packetd/services/kernel"
	"github.com/untangle/packetd/services/logger"
	"net"
	"time"
)

// SubscriptionHolder stores the details of a data callback subscription
type SubscriptionHolder struct {
	Owner         string
	Priority      int
	NfqueueFunc   NfqueueHandlerFunction
	ConntrackFunc ConntrackHandlerFunction
	NetloggerFunc NetloggerHandlerFunction
}

var shutdownCleanerTask = make(chan bool)

// Startup starts the event handling service
func Startup() {
	// create the session, conntrack, and certificate tables
	sessionTable = make(map[uint32]*SessionEntry)
	conntrackTable = make(map[uint32]*ConntrackEntry)

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
		logger.Err("Failed to properly shutdown cleanerTask\n")
	}
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
			logger.Debug("Calling cleaner task %d\n", counter)
			cleanSessionTable()
			cleanConntrackTable()
		}
	}
}

//dupIP makes a copy of a net.IP
func dupIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}
