package dispatch

import (
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/untangle/packetd/services/kernel"
	"github.com/untangle/packetd/services/logger"
)

// NfDrop is NF_DROP constant
const NfDrop = 0

// NfAccept is the NF_ACCEPT constant
const NfAccept = 1

// PacketdBypassTimeout defines the time a bypass_packetd set entry should live in milliseconds
const PacketdBypassTimeout = 0

//NfqueueHandlerFunction defines a pointer to a nfqueue callback function
type NfqueueHandlerFunction func(NfqueueMessage, uint32, bool) NfqueueResult

// NfqueueMessage is used to pass nfqueue traffic to interested plugins
type NfqueueMessage struct {
	Session        *Session
	MsgTuple       Tuple
	Family         int
	Packet         gopacket.Packet
	PacketMark     uint32
	Length         int
	ClientToServer bool
	IP4Layer       *layers.IPv4
	IP6Layer       *layers.IPv6
	TCPLayer       *layers.TCP
	UDPLayer       *layers.UDP
	ICMPv4Layer    *layers.ICMPv4
	Payload        []byte
}

// NfqueueResult returns status and other information from a subscription handler function
type NfqueueResult struct {
	SessionRelease bool
}

// subscriberResult returns status and other information from a subscription handler function
type subscriberResult struct {
	owner          string
	sessionRelease bool
}

// ReleaseSession is called by a subscriber to stop receiving traffic for a session
func ReleaseSession(session *Session, owner string) {
	session.subLocker.RLock()
	origLen := len(session.subscriptions)
	session.subLocker.RUnlock()

	if origLen == 0 {
		return
	}

	session.subLocker.Lock()
	delete(session.subscriptions, owner)
	len := len(session.subscriptions)
	if origLen != len {
		logger.Debug("Removing %s session nfqueue subscription for session %d\n", owner, session.GetConntrackID())
	}
	if len == 0 {
		logger.Debug("Zero subscribers reached - settings bypass_packetd=true for session %d\n", session.GetConntrackID())
		kernel.BypassViaNftSet(session.GetConntrackID(), PacketdBypassTimeout)
	}
	session.subLocker.Unlock()
}

// nfqueueCallback is the callback for the packet
// return the mark to set on the packet
func nfqueueCallback(ctid uint32, family uint32, packet gopacket.Packet, packetLength int, pmark uint32) int {
	var mess NfqueueMessage
	//printSessionTable()

	mess.Family = int(family)
	mess.Packet = packet
	mess.PacketMark = pmark
	mess.Length = packetLength

	// get the IPv4 and IPv6 layers
	ip4Layer := mess.Packet.Layer(layers.LayerTypeIPv4)
	ip6Layer := mess.Packet.Layer(layers.LayerTypeIPv6)

	if ip4Layer != nil {
		mess.IP4Layer = ip4Layer.(*layers.IPv4)
		mess.MsgTuple.Protocol = uint8(mess.IP4Layer.Protocol)
		mess.MsgTuple.ClientAddress = dupIP(mess.IP4Layer.SrcIP)
		mess.MsgTuple.ServerAddress = dupIP(mess.IP4Layer.DstIP)
	} else if ip6Layer != nil {
		mess.IP6Layer = ip6Layer.(*layers.IPv6)
		mess.MsgTuple.Protocol = uint8(mess.IP6Layer.NextHeader)
		mess.MsgTuple.ClientAddress = dupIP(mess.IP6Layer.SrcIP)
		mess.MsgTuple.ServerAddress = dupIP(mess.IP6Layer.DstIP)
	} else {
		return NfAccept
	}

	// we shouldn't be queueing loopback packets
	// if we catch one throw a warning
	if mess.MsgTuple.ClientAddress.IsLoopback() || mess.MsgTuple.ServerAddress.IsLoopback() {
		logger.Warn("nfqueue event for loopback packet: %v\n", mess.MsgTuple)
		return NfAccept
	}

	newSession := ((pmark & 0x10000000) != 0)

	// get the TCP layer
	tcpLayer := mess.Packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		mess.TCPLayer = tcpLayer.(*layers.TCP)
		mess.MsgTuple.ClientPort = uint16(mess.TCPLayer.SrcPort)
		mess.MsgTuple.ServerPort = uint16(mess.TCPLayer.DstPort)
	}

	// get the UDP layer
	udpLayer := mess.Packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		mess.UDPLayer = udpLayer.(*layers.UDP)
		mess.MsgTuple.ClientPort = uint16(mess.UDPLayer.SrcPort)
		mess.MsgTuple.ServerPort = uint16(mess.UDPLayer.DstPort)
	}

	// get the Application layer
	appLayer := mess.Packet.ApplicationLayer()
	if appLayer != nil {
		mess.Payload = appLayer.Payload()
	}

	if logger.IsTraceEnabled() {
		logger.Trace("nfqueue event[%d]: %v 0x%08x\n", ctid, mess.MsgTuple, pmark)
	}

	session := findSession(ctid)

	if session == nil {
		if !newSession {
			// If we did not find the session in the session table, and this isn't a new packet
			// Then we somehow missed the first packet - Just mark the connection as bypassed
			// and return the packet
			// This is common in a few scenarios, so just log those as debug statements
			if mess.TCPLayer != nil && mess.TCPLayer.RST {
				logger.Debug("Ignoring mid-session RST packet: %s %d\n", mess.MsgTuple, ctid)
			} else if mess.TCPLayer != nil && mess.TCPLayer.FIN {
				logger.Debug("Ignoring mid-session FIN packet: %s %d\n", mess.MsgTuple, ctid)
			} else {
				logger.Info("Ignoring mid-session packet: %s %d\n", mess.MsgTuple, ctid)
			}

			kernel.BypassViaNftSet(ctid, PacketdBypassTimeout)
			return NfAccept
		}
		session = createSession(mess, ctid)
		mess.Session = session
	} else {
		if newSession {
			if mess.MsgTuple.Equal(session.GetClientSideTuple()) {
				// netfilter considers this a "new" session, but the tuple is identical.
				// this happens because netfilter's session tracking is more advanced
				// and often parses deeper headers (ping/dns) to track sessions
				// in this case, we don't count it as a new session, just reuse the old one
				newSession = false
			} else {
				// the packet tuple does not match the session tuple
				// this happens in several cases:

				// 1) This is actually a different session with the same ctid
				// the previous session/ctid never reached the conntrack confirmed state
				// either because it was dropped or it got merged with another conntrack id
				// either way - this new session is the official session of the ctid and the old one is dead

				// 2) This is a new session/ctid that is being reused for a session
				// that has just died but we have not yet processed a the conntrack event
				// nothing guarantees that we get the conntrack DELETE event before ctid gets reused in a new session
				// in this case we can also just delete the old mapping from the session table, but leave
				// it in the conntrack table for the conntrack handle to handle

				logger.Debug("Conflicting session [%d] %v != %v\n", ctid, mess.MsgTuple, session.GetClientSideTuple())
				// We don't need to flush here - this is a new session its already been flushed
				// session.flushDict()
				session.removeFromSessionTable()
				session = createSession(mess, ctid)
				mess.Session = session
			}
		}

		// Also check that the conntrack ID matches. Log an error if it does not
		if session.GetConntrackID() != ctid {
			logger.Err("%OC|Conntrack ID mismatch: %s  %d != %d %v\n", "conntrack_id_mismatch", 0, mess.MsgTuple, ctid, session.GetConntrackID(), session.GetConntrackConfirmed())
		}
	}

	mess.Session = session

	// Sanity check - if this is a new session we should not have an existing conntrack entry (yet)
	// This does occur under normal circumstatnces when a ctid gets reused, and we get an
	// nfqueue event for the new session (same ctid) before we get the conntrack delete event
	if newSession {
		conntrack, _ := findConntrack(ctid)
		if conntrack != nil {
			logger.Debug("Found existing conntrack (ctid: %v) for new session:\n", ctid)
			logger.Debug("New Session        : %v\n", mess.MsgTuple)
			logger.Debug("Existing Conntrack : %v\n", conntrack.ClientSideTuple)
			logger.Debug("Removing previous conntrack.\n")
		}
		removeConntrack(ctid)
	}

	if mess.MsgTuple.ClientAddress.Equal(session.GetClientSideTuple().ClientAddress) {
		mess.ClientToServer = true
	} else {
		mess.ClientToServer = false
	}

	// if this is a new session set the client side interface index and type
	if newSession {
		session.SetClientInterfaceID(uint8((pmark & 0x000000FF)))
		session.SetClientInterfaceType(uint8((pmark & 0x03000000) >> 24))
	}

	// if this is a server-to-client packet and the server interface info is not
	// set yet, we can set it now (normally this is set during the conntrack new event)
	// but in some cases we get the response packet first
	if !mess.ClientToServer && session.GetServerInterfaceID() == 0 {
		session.SetServerInterfaceID(uint8((pmark & 0x000000FF)))
		session.SetServerInterfaceType(uint8((pmark & 0x03000000) >> 24))
	}

	// Update some accounting bits
	session.SetLastActivity(time.Now())
	session.AddPacketCount(1)
	session.AddByteCount(uint64(mess.Length))
	session.AddEventCount(1)

	// call the subscribers
	return callSubscribers(ctid, session, mess, pmark, newSession)
}

// callSubscribers calls all the nfqueue message subscribers (plugins)
// and returns a verdict and the new mark
func callSubscribers(ctid uint32, session *Session, mess NfqueueMessage, pmark uint32, newSession bool) int {
	resultsChannel := make(chan subscriberResult)

	// We loop and increment the priority until all subscriptions have been called
	sublist := MirrorNfqueueSubscriptions(session)
	subtotal := len(sublist)

	// If there are no subscribers anymore, just release now
	if subtotal == 0 {
		kernel.BypassViaNftSet(session.GetConntrackID(), PacketdBypassTimeout)
		return NfAccept
	}

	subcount := 0
	priority := 0

	for subcount != subtotal {
		// Counts the total number of calls made for each priority so we know
		// how many NfqueueResult's to read from the result channel
		hitcount := 0

		// Call all of the subscribed handlers for the current priority
		for key, val := range sublist {
			if val.Priority != priority {
				continue
			}
			// handle each subscriber on a goroutine
			go func(key string, val SubscriptionHolder, pri int) {
				if logger.IsTraceEnabled() {
					logger.Trace("Calling nfqueue PLUGIN:%s PRI:%d CTID:%d\n", key, pri, ctid)
				}

				timeoutTimer := time.NewTimer(maxSubscriberTime)
				c := make(chan subscriberResult, 1)

				// call the subscriber hook on another goroutine so we can timeout while waiting for the result
				go func() {
					result := val.NfqueueFunc(mess, ctid, newSession)
					stat := timeoutTimer.Stop()
					// if we stopped the timer then stat will be true and we need to write the subscriber result
					// to the channel, otherwise don't bother since a release was written by the timeout handler
					if stat == true {
						c <- subscriberResult{owner: key, sessionRelease: result.SessionRelease}
					}
				}()

				// wait for the subscriber to finish or the timeout to trigger
				select {
				case result := <-c:
					// put what the subscriber returned in the result channel
					resultsChannel <- result
				case <-timeoutTimer.C:
					// the subscriber took too long so put a release in the result channel on behalf of the subscriber
					logger.Crit("%OC|Timeout while processing nfqueue - subscriber:%s\n", "timeout_nfqueue_"+key, 0, key)
					resultsChannel <- subscriberResult{owner: key, sessionRelease: true}
				}
			}(key, val, priority)
			hitcount++
			subcount++
		}

		// get the results for each called subscriber and remove the session
		// subscription for any that set the SessionRelease flag
		for i := 0; i < hitcount; i++ {
			select {
			case result := <-resultsChannel:
				if result.sessionRelease {
					ReleaseSession(session, result.owner)
				}
			}
		}

		// Increment the priority and keep looping until we've called all subscribers
		priority++
		if priority > 100 {
			logger.Err("%OC|Priority > 100 Constraint failed! %d %d %d %v", "nfqueue_priority_constraint", 0, subcount, subtotal, priority, sublist)
			panic("Constraint failed - infinite loop detected")
		}
	}

	// return the updated mark to be set on the packet
	return NfAccept
}

// createSession creates a new session and inserts the forward mapping
// into the session table
func createSession(mess NfqueueMessage, ctid uint32) *Session {
	session := new(Session)
	session.SetSessionID(nextSessionID())
	session.SetConntrackID(ctid)
	session.SetCreationTime(time.Now())
	session.SetPacketCount(1)
	session.SetByteCount(uint64(mess.Length))
	session.SetEventCount(1)
	session.SetLastActivity(time.Now())
	session.SetClientSideTuple(mess.MsgTuple)
	session.SetFamily(uint8(mess.Family))
	session.SetConntrackConfirmed(false)
	session.attachments = make(map[string]interface{})
	AttachNfqueueSubscriptions(session)
	insertSessionTable(ctid, session)
	return session
}

// getMicroseconds returns the current clock in microseconds
func getMicroseconds() int64 {
	return time.Now().UnixNano() / int64(time.Microsecond)
}
