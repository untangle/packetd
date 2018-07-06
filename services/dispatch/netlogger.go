package dispatch

import (
	"github.com/untangle/packetd/services/logger"
	"sync"
)

//NetloggerHandlerFunction defines a pointer to a netlogger callback function
type NetloggerHandlerFunction func(*NetloggerMessage)

// NetloggerMessage is used to pass the details of NFLOG events to interested plugins
type NetloggerMessage struct {
	Version      uint8
	Protocol     uint8
	IcmpType     uint16
	SrcInterface uint8
	DstInterface uint8
	SrcAddress   string
	DstAddress   string
	SrcPort      uint16
	DstPort      uint16
	Mark         uint32
	Prefix       string
}

var netloggerList map[string]SubscriptionHolder
var netloggerListMutex sync.Mutex

// InsertNetloggerSubscription adds a subscription for receiving netlogger messages
func InsertNetloggerSubscription(owner string, priority int, function NetloggerHandlerFunction) {
	var holder SubscriptionHolder
	logger.LogInfo("Adding Netlogger Event Subscription (%s, %d)\n", owner, priority)

	holder.Owner = owner
	holder.Priority = priority
	holder.NetloggerFunc = function
	netloggerListMutex.Lock()
	netloggerList[owner] = holder
	netloggerListMutex.Unlock()
}

func netloggerCallback(version uint8,
	protocol uint8, icmpType uint16,
	srcInterface uint8, dstInterface uint8,
	srcAddress string, dstAddress string,
	srcPort uint16, dstPort uint16, mark uint32, prefix string) {
	var netlogger NetloggerMessage

	netlogger.Version = version
	netlogger.Protocol = protocol
	netlogger.IcmpType = icmpType
	netlogger.SrcInterface = srcInterface
	netlogger.DstInterface = dstInterface
	netlogger.SrcAddress = srcAddress
	netlogger.DstAddress = dstAddress
	netlogger.SrcPort = srcPort
	netlogger.DstPort = dstPort
	netlogger.Mark = mark
	netlogger.Prefix = prefix

	logger.LogTrace("netlogger event: %v \n", netlogger)

	// We loop and increment the priority until all subscriptions have been called
	sublist := netloggerList
	subtotal := len(sublist)
	subcount := 0
	priority := 0

	for subcount != subtotal {
		var wg sync.WaitGroup

		// Call all of the subscribed handlers for the current priority
		for key, val := range sublist {
			if val.Priority != priority {
				continue
			}
			logger.LogDebug("Calling netlogger APP:%s PRIORITY:%d\n", key, priority)
			wg.Add(1)
			go func(val SubscriptionHolder) {
				val.NetloggerFunc(&netlogger)
				wg.Done()
				logger.LogDebug("Finished netlogger APP:%s PRIORITY:%d\n", key, priority)
			}(val)
			subcount++

		}

		// Wait on all of this priority to finish
		wg.Wait()

		// Increment the priority and keep looping until we've called all subscribers
		priority++
	}
}
