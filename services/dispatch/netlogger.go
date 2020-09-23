package dispatch

import (
	"strings"
	"sync"
	"time"

	"github.com/untangle/packetd/services/logger"
)

//NetloggerHandlerFunction defines a pointer to a netlogger callback function
type NetloggerHandlerFunction func(*NetloggerMessage)

// NetloggerMessage is used to pass the details of NFLOG events to interested plugins
type NetloggerMessage struct {
	Sessptr      *Session
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
	Ctid         uint32
	Prefix       string
}

func netloggerCallback(version uint8,
	protocol uint8, icmpType uint16,
	srcInterface uint8, dstInterface uint8,
	srcAddress string, dstAddress string,
	srcPort uint16, dstPort uint16,
	mark uint32, ctid uint32, prefix string) {
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
	netlogger.Prefix = strings.Replace(prefix, "'", "\"", -1)
	netlogger.Sessptr = findSession(ctid)

	logger.Trace("netlogger event: %v \n", netlogger)

	// We loop and increment the priority until all subscriptions have been called
	sublist := netloggerSubList
	subtotal := len(sublist)
	subcount := 0
	priority := 0

	for subcount != subtotal {
		timeoutTimer := time.NewTimer(maxSubscriberTime)
		var wg sync.WaitGroup

		// Call all of the subscribed handlers for the current priority
		for key, val := range sublist {
			if val.Priority != priority {
				continue
			}
			logger.Debug("Calling netlogger APP:%s PRIORITY:%d\n", key, priority)
			wg.Add(1)
			go func(val SubscriptionHolder, wg *sync.WaitGroup, key string, priority int) {
				defer wg.Done()
				val.NetloggerFunc(&netlogger)
				logger.Debug("Finished netlogger APP:%s PRIORITY:%d\n", key, priority)
			}(val, &wg, key, priority)
			subcount++

		}

		// Wait for all of this priority to finish. Calling the wait on a goroutine that closes a
		// channel allows us to wait for either the channel to close or the subscriber timeout
		c := make(chan bool)
		go func(c chan bool, wg *sync.WaitGroup) {
			defer close(c)
			wg.Wait()
		}(c, &wg)
		select {
		case <-timeoutTimer.C:
			logger.Crit("%OC|Timeout while waiting for netlogger subcriber:%s\n", "timeout_netlogger", 0)
		case <-c:
			timeoutTimer.Stop()
		}

		// Increment the priority and keep looping until we've called all subscribers
		priority++
		if priority > 100 {
			logger.Err("Priority > 100 Constraint failed! %d %d %d %v", subcount, subtotal, priority, sublist)
			panic("Constraint failed - infinite loop detected")
		}
	}
}
