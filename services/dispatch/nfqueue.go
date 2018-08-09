package dispatch

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/untangle/packetd/services/logger"
	"sync"
	"time"
)

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
	session.Subs = make(map[string]SubscriptionHolder)

	for index, element := range nfqueueList {
		session.Subs[index] = element
	}
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

	var session *SessionEntry
	var ok bool
	var newSession = false

	// If we already have a session entry update the existing, otherwise create a new entry for the table.
	if session, ok = findSessionEntry(ctid); ok {
		logger.Trace("Session Found %d in table\n", ctid)
		session.LastActivityTime = time.Now()
		session.PacketCount++
		session.ByteCount += uint64(packetLength)
		session.EventCount++
		// the packet tuple should either match the client side tuple
		// or
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
		newSession = true
		session = new(SessionEntry)
		session.SessionID = nextSessionID()
		session.CreationTime = time.Now()
		session.PacketCount = 1
		session.ByteCount = uint64(packetLength)
		session.LastActivityTime = time.Now()
		session.ClientSideTuple = mess.Tuple
		session.EventCount = 1
		session.ConntrackConfirmed = false
		session.attachments = make(map[string]interface{})
		AttachNfqueueSubscriptions(session)
		insertSessionEntry(ctid, session)
	}

	mess.Session = session

	pipe := make(chan NfqueueResult)

	// We loop and increment the priority until all subscriptions have been called
	subtotal := len(session.Subs)
	subcount := 0
	priority := 0

	for subcount != subtotal {
		// Counts the total number of calls made for each priority so we know
		// how many NfqueueResult's to read from the result channel
		hitcount := 0

		// Call all of the subscribed handlers for the current priority
		for key, val := range session.Subs {
			if val.Priority != priority {
				continue
			}
			logger.Debug("Calling nfqueue APP:%s PRIORITY:%d\n", key, priority)
			go func(key string, val SubscriptionHolder) {
				pipe <- val.NfqueueFunc(mess, ctid, newSession)
				logger.Debug("Finished nfqueue APP:%s PRIORITY:%d\n", key, priority)
			}(key, val)
			hitcount++
			subcount++
		}

		// Add the mark bits returned from each handler and remove the session
		// subscription for any that set the SessionRelease flag
		for i := 0; i < hitcount; i++ {
			select {
			case result := <-pipe:
				pmark |= result.PacketMark
				if result.SessionRelease {
					logger.Debug("Removing %s session nfqueue subscription for %d\n", result.Owner, uint32(ctid))
					delete(session.Subs, result.Owner)
				}
			}
		}

		// Increment the priority and keep looping until we've called all subscribers
		priority++
	}

	// return the updated mark to be set on the packet
	return (pmark)
}
