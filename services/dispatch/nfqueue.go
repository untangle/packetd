package dispatch

import (
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/untangle/packetd/services/dict"
	"github.com/untangle/packetd/services/logger"
)

// maxAllowedTime is the maximum time a plugin is allowed to process a packet.
// If this time is exceeded. The warning is logged and the packet is passed
// and the session released on behalf of the offending plugin
const maxAllowedTime = 30 * time.Second

// NfDrop is NF_DROP constant
const NfDrop = 0

// NfAccept is the NF_ACCEPT constant
const NfAccept = 1

//NfqueueHandlerFunction defines a pointer to a nfqueue callback function
type NfqueueHandlerFunction func(NfqueueMessage, uint32, bool) NfqueueResult

// NfqueueMessage is used to pass nfqueue traffic to interested plugins
type NfqueueMessage struct {
	Session        *SessionEntry
	MsgTuple       Tuple
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
func ReleaseSession(session *SessionEntry, owner string) {
	session.subLocker.Lock()
	defer session.subLocker.Unlock()
	origLen := len(session.subscriptions)
	if origLen == 0 {
		return
	}
	delete(session.subscriptions, owner)
	len := len(session.subscriptions)
	if origLen != len {
		logger.Debug("Removing %s session nfqueue subscription for session %d\n", owner, session.ConntrackID)
	}
	if len == 0 {
		logger.Debug("Zero subscribers reached - settings bypass_packetd=true for session %d\n", session.ConntrackID)
		dict.AddSessionEntry(session.ConntrackID, "bypass_packetd", true)
	}
}

// nfqueueCallback is the callback for the packet
// return the mark to set on the packet
func nfqueueCallback(ctid uint32, packet gopacket.Packet, packetLength int, pmark uint32) int {
	var mess NfqueueMessage
	//printSessionTable()

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
		mess.MsgTuple.Protocol = uint8(mess.IP6Layer.NextHeader) // FIXME - is this the correct field?
		mess.MsgTuple.ClientAddress = dupIP(mess.IP6Layer.SrcIP)
		mess.MsgTuple.ServerAddress = dupIP(mess.IP6Layer.DstIP)
	} else {
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

	logger.Trace("nfqueue event[%d]: %v 0x%08x\n", ctid, mess.MsgTuple, pmark)

	session := findSessionEntry(ctid)

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
				if mess.TCPLayer != nil {
					logger.Info("TCP flags: [SYN: %v FIN: %v RST: %v ACK: %v]\n", mess.TCPLayer.SYN, mess.TCPLayer.FIN, mess.TCPLayer.RST, mess.TCPLayer.ACK)
				}
			}

			dict.AddSessionEntry(ctid, "bypass_packetd", true)
			return NfAccept
		}
		session = createSessionEntry(mess, ctid)
		mess.Session = session
	} else {
		if newSession {

			if mess.MsgTuple.Equal(session.ClientSideTuple) {
				// netfilter considers this a "new" session, but the tuple is identical.
				// this happens because netfilter's session tracking is more advanced
				// and often parses deeper headers (ping/dns) to track sessions
				// in this case, we don't count it as a new session, just reuse the old one
				newSession = false
			} else {
				// If this is a new session and a session was found, it may have just been an aborted session
				// (The first packet was dropped before conntrack confirm)
				// In this case, just drop the old session. However, if the old session was conntrack confirmed
				// something is not correct.
				if session.ConntrackConfirmed {
					logger.Err("Conflicting session tuple [%d] %v != %v\n", ctid, mess.MsgTuple, session.ClientSideTuple)
					logger.Err("Packet Tuple: %v\n", mess.MsgTuple)
					logger.Err("Previous Session Information:\n")
					logger.Err("ClientSideTuple: %v\n", session.ClientSideTuple)
					logger.Err("ServerSideTuple: %v\n", session.ServerSideTuple)
					logger.Err("CreationTime: %v ago\n", time.Now().Sub(session.CreationTime))
					logger.Err("LastActivityTime: %v ago\n", time.Now().Sub(session.LastActivityTime))
					logger.Err("Packets: %v\n", session.PacketCount)
					logger.Err("Bytes: %v\n", session.ByteCount)
					logger.Err("Events: %v\n", session.EventCount)
					if session.ConntrackEntry != nil {
						logger.Err("Conntrack ID: %v\n", session.ConntrackEntry.ConntrackID)
						logger.Err("Conntrack ClientSideTuple: %v\n", session.ConntrackEntry.ClientSideTuple)
						logger.Err("Conntrack ServerSideTuple: %v\n", session.ConntrackEntry.ServerSideTuple)
						logger.Err("Conntrack CreationTime: %v\n", time.Now().Sub(session.ConntrackEntry.CreationTime))
						logger.Err("Conntrack LastActivityTime: %v\n", time.Now().Sub(session.ConntrackEntry.LastActivityTime))
					}
				} else {
					logger.Debug("Conflicting session tuple [%d] %v != %v\n", ctid, mess.MsgTuple, session.ClientSideTuple)
				}

				removeSessionEntry(ctid)
				session = createSessionEntry(mess, ctid)
				mess.Session = session
			}
		}

		// Also check that the conntrack ID matches. Log an error if it does not
		if session.ConntrackID != ctid {
			logger.Err("Conntrack ID mismatch: %s  %d != %d %v\n", mess.MsgTuple, ctid, session.ConntrackID, session.ConntrackConfirmed)
		}
	}

	mess.Session = session

	if mess.MsgTuple.ClientAddress.Equal(session.ClientSideTuple.ClientAddress) {
		mess.ClientToServer = true
	} else {
		mess.ClientToServer = false
	}

	// Update some accounting bits
	session.LastActivityTime = time.Now()
	session.PacketCount++
	session.ByteCount += uint64(mess.Length)
	session.EventCount++

	return callSubscribers(ctid, session, mess, pmark, newSession)
}

// callSubscribers calls all the nfqueue message subscribers (plugins)
// and returns a verdict and the new mark
func callSubscribers(ctid uint32, session *SessionEntry, mess NfqueueMessage, pmark uint32, newSession bool) int {
	resultsChannel := make(chan subscriberResult)

	// We loop and increment the priority until all subscriptions have been called
	sublist := MirrorNfqueueSubscriptions(session)
	subtotal := len(sublist)
	subcount := 0
	priority := 0
	var timeMap = make(map[string]float64)
	var timeMapLock = sync.RWMutex{}

	for subcount != subtotal {
		// Counts the total number of calls made for each priority so we know
		// how many NfqueueResult's to read from the result channel
		hitcount := 0

		// Call all of the subscribed handlers for the current priority
		for key, val := range sublist {
			if val.Priority != priority {
				continue
			}
			logger.Trace("Calling nfqueue PLUGIN:%s PRI:%d CTID:%d\n", key, priority, ctid)
			go func(key string, val SubscriptionHolder) {
				timeoutTimer := time.NewTimer(maxAllowedTime)
				c := make(chan subscriberResult, 1)
				t1 := getMicroseconds()

				go func() {
					result := val.NfqueueFunc(mess, ctid, newSession)
					c <- subscriberResult{owner: key, sessionRelease: result.SessionRelease}
				}()

				select {
				case result := <-c:
					resultsChannel <- result
					timeoutTimer.Stop()
				case <-timeoutTimer.C:
					logger.Err("Timeout reached while processing nfqueue. plugin:%s\n", key)
					c <- subscriberResult{owner: key, sessionRelease: true}
				}

				timediff := (float64(getMicroseconds()-t1) / 1000.0)
				timeMapLock.Lock()
				timeMap[val.Owner] = timediff
				timeMapLock.Unlock()

				logger.Trace("Finished nfqueue PLUGIN:%s PRI:%d CTID:%d ms:%.1f\n", key, priority, ctid, timediff)
			}(key, val)
			hitcount++
			subcount++
		}

		// Add the mark bits returned from each handler and remove the session
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
			logger.Err("Priority > 100 Constraint failed! %d %d %d %v", subcount, subtotal, priority, sublist)
			panic("Constraint failed - infinite loop detected")
		}
	}

	if logger.IsLogEnabledSource(logger.LogLevelTrace, "dispatch_timer") {
		timeMapLock.RLock()
		logger.LogMessageSource(logger.LogLevelTrace, "dispatch_timer", "Timer Map: %v\n", timeMap)
		timeMapLock.RUnlock()
	}

	// return the updated mark to be set on the packet
	return NfAccept
}

// createSessionEntry creates a new session and inserts the forward mapping
// into the session table
func createSessionEntry(mess NfqueueMessage, ctid uint32) *SessionEntry {
	session := new(SessionEntry)
	session.SessionID = nextSessionID()
	session.ConntrackID = ctid
	session.CreationTime = time.Now()
	session.PacketCount = 1
	session.ByteCount = uint64(mess.Length)
	session.LastActivityTime = time.Now()
	session.ClientSideTuple = mess.MsgTuple
	session.EventCount = 1
	session.ConntrackConfirmed = false
	session.attachments = make(map[string]interface{})
	AttachNfqueueSubscriptions(session)
	logger.Trace("Session Adding %d to table\n", ctid)
	insertSessionEntry(ctid, session)
	return session
}

// getMicroseconds returns the current clock in microseconds
func getMicroseconds() int64 {
	return time.Now().UnixNano() / int64(time.Microsecond)
}
