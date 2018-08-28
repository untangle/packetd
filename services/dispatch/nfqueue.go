package dispatch

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	//"github.com/untangle/packetd/services/dict"
	"github.com/untangle/packetd/services/logger"
	"sync"
	"time"
)

const maxAllowedTime = 30 * time.Second

//NfqueueHandlerFunction defines a pointer to a nfqueue callback function
type NfqueueHandlerFunction func(NfqueueMessage, uint32, bool) NfqueueResult

// NfqueueResult returns status and other information from a subscription handler function
type NfqueueResult struct {
	Owner          string
	PacketMark     uint32
	SessionRelease bool
}

// NfqueueMessage is used to pass nfqueue traffic to interested plugins
type NfqueueMessage struct {
	Session  *SessionEntry
	Tuple    Tuple
	Packet   gopacket.Packet
	Length   int
	IP4layer *layers.IPv4
	IP6layer *layers.IPv6
	TCPlayer *layers.TCP
	UDPlayer *layers.UDP
	Payload  []byte
}

var nfqueueList map[string]SubscriptionHolder
var nfqueueListMutex sync.Mutex

// InsertNfqueueSubscription adds a subscription for receiving nfqueue messages
func InsertNfqueueSubscription(owner string, priority int, function NfqueueHandlerFunction) {
	var holder SubscriptionHolder
	logger.Info("Adding NFQueue Event Subscription (%s, %d)\n", owner, priority)

	holder.Owner = owner
	holder.Priority = priority
	holder.NfqueueFunc = function
	nfqueueListMutex.Lock()
	nfqueueList[owner] = holder
	nfqueueListMutex.Unlock()
}

// AttachNfqueueSubscriptions attaches active nfqueue subscriptions to the argumented SessionEntry
func AttachNfqueueSubscriptions(session *SessionEntry) {
	session.subLocker.Lock()
	session.subscriptions = make(map[string]SubscriptionHolder)

	for index, element := range nfqueueList {
		session.subscriptions[index] = element
	}
	session.subLocker.Unlock()
}

// ReleaseSession is called by a subscriber to stop receiving traffic for a session
func ReleaseSession(session *SessionEntry, owner string) {
	logger.Debug("Removing %s session nfqueue subscription for session %d\n", owner, session.SessionID)
	session.subLocker.Lock()
	delete(session.subscriptions, owner)
	if len(session.subscriptions) == 0 {
		logger.Debug("Zero subscribers reached - settings bypass_packetd=true for session %d\n", session.SessionID)
		dict.AddSessionEntry(session.ConntrackID, "bypass_packetd", true)
	}
	session.subLocker.Unlock()
}

// nfqueueCallback is the callback for the packet
// return the mark to set on the packet
func nfqueueCallback(ctid uint32, packet gopacket.Packet, packetLength int, pmark uint32) uint32 {
	var mess NfqueueMessage
	//printSessionTable()

	mess.Packet = packet
	mess.Length = packetLength

	// get the IPv4 and IPv6 layers
	ip4Layer := mess.Packet.Layer(layers.LayerTypeIPv4)
	ip6Layer := mess.Packet.Layer(layers.LayerTypeIPv6)

	if ip4Layer != nil {
		mess.IP4layer = ip4Layer.(*layers.IPv4)
		mess.Tuple.Protocol = uint8(mess.IP4layer.Protocol)
		mess.Tuple.ClientAddress = dupIP(mess.IP4layer.SrcIP)
		mess.Tuple.ServerAddress = dupIP(mess.IP4layer.DstIP)
	} else if ip6Layer != nil {
		mess.IP6layer = ip6Layer.(*layers.IPv6)
		mess.Tuple.Protocol = uint8(mess.IP6layer.NextHeader) // FIXME - is this the correct field?
		mess.Tuple.ClientAddress = dupIP(mess.IP6layer.SrcIP)
		mess.Tuple.ServerAddress = dupIP(mess.IP6layer.DstIP)
	} else {
		return (pmark)
	}

	// get the TCP layer
	tcpLayer := mess.Packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		mess.TCPlayer = tcpLayer.(*layers.TCP)
		mess.Tuple.ClientPort = uint16(mess.TCPlayer.SrcPort)
		mess.Tuple.ServerPort = uint16(mess.TCPlayer.DstPort)
	}

	// get the UDP layer
	udpLayer := mess.Packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		mess.UDPlayer = udpLayer.(*layers.UDP)
		mess.Tuple.ClientPort = uint16(mess.UDPlayer.SrcPort)
		mess.Tuple.ServerPort = uint16(mess.UDPlayer.DstPort)
	}

	// get the Application layer
	appLayer := mess.Packet.ApplicationLayer()
	if appLayer != nil {
		mess.Payload = appLayer.Payload()
	}

	logger.Trace("nfqueue event[%d]: %v \n", ctid, mess.Tuple)

	session, newflag := obtainSessionEntry(mess, ctid)
	mess.Session = session

	resultsChannel := make(chan NfqueueResult)

	// We loop and increment the priority until all subscriptions have been called
	subtotal := len(session.subscriptions)
	subcount := 0
	priority := 0
	var timeMap = make(map[string]float64)
	var timeMapLock = sync.RWMutex{}

	for subcount != subtotal {
		// Counts the total number of calls made for each priority so we know
		// how many NfqueueResult's to read from the result channel
		hitcount := 0

		// Call all of the subscribed handlers for the current priority
		for key, val := range session.subscriptions {
			if val.Priority != priority {
				continue
			}
			logger.Trace("Calling nfqueue  plugin:%s priority:%d session_id:%d\n", key, priority, session.SessionID)
			go func(key string, val SubscriptionHolder) {
				timeoutTimer := time.NewTimer(maxAllowedTime)
				c := make(chan NfqueueResult, 1)
				t1 := getMicroseconds()

				go func() { c <- val.NfqueueFunc(mess, ctid, newflag) }()

				select {
				case result := <-c:
					resultsChannel <- result
					timeoutTimer.Stop()
				case <-timeoutTimer.C:
					logger.Err("Timeout reached while processing nfqueue. plugin:%s\n", key)
					resultsChannel <- NfqueueResult{Owner: key, PacketMark: 0, SessionRelease: true}
				}

				timediff := (float64(getMicroseconds()-t1) / 1000.0)
				timeMapLock.Lock()
				timeMap[val.Owner] = timediff
				timeMapLock.Unlock()

				logger.Trace("Finished nfqueue plugin:%s PRI:%d SID:%d ms:%.1f\n", key, priority, session.SessionID, timediff)
			}(key, val)
			hitcount++
			subcount++
		}

		// Add the mark bits returned from each handler and remove the session
		// subscription for any that set the SessionRelease flag
		for i := 0; i < hitcount; i++ {
			select {
			case result := <-resultsChannel:
				pmark |= result.PacketMark
				if result.SessionRelease {
					ReleaseSession(session, result.Owner)
				}
			}
		}

		// Increment the priority and keep looping until we've called all subscribers
		priority++
		if priority > 100 {
			logger.Err("Priority > 100 Constraint failed! %d %d %d %v", subcount, subtotal, priority, session.subscriptions)
			panic("Constraint failed - infinite loop detected")
		}
	}

	if logger.IsLogEnabledSource(logger.LogLevelTrace, "dispatch_timer") {
		timeMapLock.RLock()
		logger.LogMessageSource(logger.LogLevelTrace, "dispatch_timer", "Timer Map: %v\n", timeMap)
		timeMapLock.RUnlock()
	}

	// return the updated mark to be set on the packet
	return (pmark)
}

// obtainSessionEntry finds an existing or creates a new Session object
func obtainSessionEntry(mess NfqueueMessage, ctid uint32) (*SessionEntry, bool) {
	var session *SessionEntry
	var newFlag bool
	var ok bool

	// If we already have a session entry update the existing, otherwise create a new entry for the table.
	if session, ok = findSessionEntry(ctid); ok {
		logger.Trace("Session Found %d in table\n", ctid)
		session.LastActivityTime = time.Now()
		session.PacketCount++
		session.ByteCount += uint64(mess.Length)
		session.EventCount++

		// the packet tuple should either match the client side tuple or the server side tuple
		if !session.ClientSideTuple.Equal(mess.Tuple) && !session.ServerSideTuple.EqualReverse(mess.Tuple) {
			var logLevel int
			logLevel = logger.LogLevelDebug
			if session.ConntrackConfirmed {
				// if conntrack has been confirmed, this is an error
				// so increase log level
				logLevel = logger.LogLevelErr
			}
			if logger.IsLogEnabled(logLevel) {
				logger.LogMessage(logLevel, "Conntrack ID Mismatch! %d\n", ctid)
				logger.LogMessage(logLevel, "  Packet Tuple: %s\n", mess.Tuple)
				logger.LogMessage(logLevel, "  Orig   Tuple: %s\n", session.ClientSideTuple.String())
				logger.LogMessage(logLevel, "  Reply  Tuple: %s\n", session.ServerSideTuple.StringReverse())
			}

			if session.ConntrackConfirmed {
				panic("CONNTRACK ID RE-USE DETECTED")
			}
			if logger.IsDebugEnabled() {
				logger.Debug("Removing stale session %d %v\n", ctid, session.ClientSideTuple)
			}
			removeSessionEntry(ctid)
			session = nil
		}

	}

	// create a new session object
	if session == nil {
		logger.Trace("Session Adding %d to table\n", ctid)
		newFlag = true
		session = new(SessionEntry)
		session.SessionID = nextSessionID()
		session.ConntrackID = ctid
		session.CreationTime = time.Now()
		session.PacketCount = 1
		session.ByteCount = uint64(mess.Length)
		session.LastActivityTime = time.Now()
		session.ClientSideTuple = mess.Tuple
		session.EventCount = 1
		session.ConntrackConfirmed = false
		session.attachments = make(map[string]interface{})
		AttachNfqueueSubscriptions(session)
		insertSessionEntry(ctid, session)
	}

	return session, newFlag
}

// getMicroseconds returns the current clock in microseconds
func getMicroseconds() int64 {
	return time.Now().UnixNano() / int64(time.Microsecond)
}
