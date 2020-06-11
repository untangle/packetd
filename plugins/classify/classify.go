// Package classify classifies sessions as certain applications
// each packet gets sent to a classd daemon (the categorization engine)
// the classd daemon returns the classification information and classify
// attaches the information to the session.
package classify

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/untangle/packetd/services/appclassmanager"
	"github.com/untangle/packetd/services/dict"
	"github.com/untangle/packetd/services/dispatch"
	"github.com/untangle/packetd/services/kernel"
	"github.com/untangle/packetd/services/logger"
	"github.com/untangle/packetd/services/reports"
)

const pluginName = "classify"

const navlStateTerminated = 0 // Indicates the connection has been terminated
const navlStateInspecting = 1 // Indicates the connection is under inspection
const navlStateMonitoring = 2 // Indicates the connection is under monitoring
const navlStateClassified = 3 // Indicates the connection is fully classified

const maxPacketCount = 64      // The maximum number of packets to inspect before releasing
const maxTrafficSize = 0x10000 // The maximum number of bytes to inspect before releasing
const maxNavlCount = 4         // The number of extra packets to inspect after NAVL is finished

type daemonSignal int

const (
	daemonNoop daemonSignal = iota
	daemonStartup
	daemonShutdown
	daemonFinished
	socketConnect
	systemStartup
	systemShutdown
)

var processChannel = make(chan daemonSignal, 1)
var socketChannel = make(chan daemonSignal, 1)
var cloudChannel = make(chan daemonSignal, 1)
var controlChannel = make(chan bool)
var classdHostPort = "127.0.0.1:8123"
var daemonAvailable = false

// PluginStartup is called to allow plugin specific initialization
func PluginStartup() {
	var err error
	var info os.FileInfo

	logger.Info("PluginStartup(%s) has been called\n", pluginName)

	//  make sure the classd binary is available
	info, err = os.Stat(daemonBinary)
	if err != nil {
		logger.Notice("Unable to check status of classify daemon %s (%v)\n", daemonBinary, err)
		return
	}

	//  make sure the classd binary is executable
	if (info.Mode() & 0111) == 0 {
		logger.Notice("Invalid file mode for classify daemon %s (%v)\n", daemonBinary, info.Mode())
		return
	}

	// we found the daemon so set our flag
	daemonAvailable = true

	// start the daemon manager to handle running the daemon process
	go daemonProcessManager(controlChannel)
	select {
	case <-controlChannel:
		logger.Info("Successful startup of daemonProcessManager\n")
	case <-time.After(10 * time.Second):
		logger.Warn("Failed to properly startup daemonProcessManager\n")
	}

	// start the socket manager to handle the daemon socket connection
	go daemonSocketManager(controlChannel)
	select {
	case <-controlChannel:
		logger.Info("Successful startup of daemonSocketManager\n")
	case <-time.After(10 * time.Second):
		logger.Warn("Failed to properly startup daemonSocketManager\n")
	}

	if !kernel.FlagNoCloud {
		// start the cloud manager to handle sending match/infer updates
		go pluginCloudManager(controlChannel)
		select {
		case <-controlChannel:
			logger.Info("Successful startup of pluginCloudManager\n")
		case <-time.After(10 * time.Second):
			logger.Warn("Failed to properly startup pluginCloudManager\n")
		}
	}

	// insert our nfqueue subscription
	dispatch.InsertNfqueueSubscription(pluginName, dispatch.ClassifyPriority, PluginNfqueueHandler)
}

// PluginShutdown is called when the daemon is shutting down
func PluginShutdown() {
	logger.Info("PluginShutdown(%s) has been called\n", pluginName)

	// make sure we created the process and socket manager before trying to stop them
	if !daemonAvailable {
		return
	}

	// signal the socket manager that the system is shutting down
	signalSocketManager(systemShutdown)
	select {
	case <-controlChannel:
		logger.Info("Successful shutdown of daemonSocketManager\n")
	case <-time.After(10 * time.Second):
		logger.Warn("Failed to properly shutdown daemonSocketManager\n")
	}

	// signal the process manager that the system is shutting down
	signalProcessManager(systemShutdown)
	select {
	case <-controlChannel:
		logger.Info("Successful shutdown of daemonProcessManager\n")
	case <-time.After(10 * time.Second):
		logger.Warn("Failed to properly shutdown daemonProcessManager\n")
	}

	if !kernel.FlagNoCloud {
		// signal the cloud manager that the system is shutting down
		signalCloudManager(systemShutdown)
		select {
		case <-controlChannel:
			logger.Info("Successful shutdown of pluginCloudManager\n")
		case <-time.After(10 * time.Second):
			logger.Warn("Failed to properly shutdown pluginCloudManager\n")
		}
	}
}

// PluginNfqueueHandler is called for raw nfqueue packets. We pass the
// packet directly to the Sandvine NAVL library for classification, and
// push the results to the conntrack dictionary.
func PluginNfqueueHandler(mess dispatch.NfqueueMessage, ctid uint32, newSession bool) dispatch.NfqueueResult {
	var reply string

	// make sure we have a valid session
	if mess.Session == nil {
		logger.Err("Ignoring event with invalid Session\n")
		return dispatch.NfqueueResult{SessionRelease: true}
	}

	// make sure we have a valid session id
	if mess.Session.GetSessionID() == 0 {
		logger.Err("Ignoring event with invalid SessionID\n")
		return dispatch.NfqueueResult{SessionRelease: true}
	}

	// make sure we have a valid IPv4 or IPv6 layer
	if mess.IP4Layer == nil && mess.IP6Layer == nil {
		logger.Err("Invalid packet: %v\n", mess.Session.GetClientSideTuple())
		return dispatch.NfqueueResult{SessionRelease: true}
	}

	// send the data to classd and read reply
	reply = classifyTraffic(&mess)

	// an empty reply means we can't talk to the daemon so just release the session
	if len(reply) == 0 {
		return dispatch.NfqueueResult{SessionRelease: true}
	}

	// process the reply and get the classification state
	state, confidence := processReply(reply, mess, ctid)

	// when NAVL is done with the session we use a counter that lets us process
	// a few extra packets to make sure we get the full classification details
	if state == navlStateClassified || state == navlStateTerminated || mess.Session.GetNavlCount() != 0 {
		mess.Session.AddNavlCount(1)
	}

	// if the daemon says the session is fully classified or terminated, or after we have seen maximum packets or data, release the session
	if mess.Session.GetNavlCount() > maxNavlCount || mess.Session.GetPacketCount() > maxPacketCount || mess.Session.GetByteCount() > maxTrafficSize {
		if logger.IsDebugEnabled() {
			logger.Debug("RELEASING SESSION:%d STATE:%d CONFIDENCE:%d PACKETS:%d BYTES:%d COUNT:%d\n", ctid, state, confidence, mess.Session.GetPacketCount(), mess.Session.GetByteCount(), mess.Session.GetNavlCount())
		}
		if !kernel.FlagNoCloud {
			analyzePrediction(mess.Session)
		}
		return dispatch.NfqueueResult{SessionRelease: true}
	}

	return dispatch.NfqueueResult{SessionRelease: false}
}

// classifyTraffic sends the packet to the daemon manager for classification and returns the result
func classifyTraffic(mess *dispatch.NfqueueMessage) string {
	var fixer gopacket.Packet
	var IP4Layer *layers.IPv4
	var IP6Layer *layers.IPv6
	var srcport uint16
	var dstport uint16
	var command string
	var proto string
	var reply string

	// For IPv4 and IPv6 we modify the packet before classify because our nftables rules give us
	// one side of traffic pre-nat and the other side post-nat. This causes classify to see two
	// different sessions, each with traffic going in a single direction, rather than a single session
	// with traffic going in both directions. This caused confusing classification results that could
	// flip-flop between two different categorizations, and it deprived NAVL of the full context it needs
	// to generate accurate results (e.g.: the server side didn't know the SNI passed by the client).
	// The approach here is to always replace the src and dst in the packet with values from the client
	// side tuple, using the ClientToServer flag to determine which info goes on which side.
	// TODO - We currently create a copy of the packet and make our changes there. It would be more
	// efficient to modify the shared packet, but deeper analysis of all potentially affected consumers
	// would have happen before making that change. For now this is probably fine.
	if mess.IP4Layer != nil {
		fixer = gopacket.NewPacket(mess.Packet.Data(), layers.LayerTypeIPv4, gopacket.Lazy)
		IP4Layer = fixer.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		proto = "IP4"
		if mess.ClientToServer {
			copy(IP4Layer.SrcIP, mess.Session.GetClientSideTuple().ClientAddress)
			copy(IP4Layer.DstIP, mess.Session.GetClientSideTuple().ServerAddress)
			srcport = mess.Session.GetClientSideTuple().ClientPort
			dstport = mess.Session.GetClientSideTuple().ServerPort
		} else {
			copy(IP4Layer.SrcIP, mess.Session.GetClientSideTuple().ServerAddress)
			copy(IP4Layer.DstIP, mess.Session.GetClientSideTuple().ClientAddress)
			srcport = mess.Session.GetClientSideTuple().ServerPort
			dstport = mess.Session.GetClientSideTuple().ClientPort
		}
	} else if mess.IP6Layer != nil {
		fixer = gopacket.NewPacket(mess.Packet.Data(), layers.LayerTypeIPv6, gopacket.Lazy)
		IP6Layer = fixer.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
		proto = "IP6"
		if mess.ClientToServer {
			copy(IP6Layer.SrcIP, mess.Session.GetClientSideTuple().ClientAddress)
			copy(IP6Layer.DstIP, mess.Session.GetClientSideTuple().ServerAddress)
			srcport = mess.Session.GetClientSideTuple().ClientPort
			dstport = mess.Session.GetClientSideTuple().ServerPort
		} else {
			copy(IP6Layer.SrcIP, mess.Session.GetClientSideTuple().ServerAddress)
			copy(IP6Layer.DstIP, mess.Session.GetClientSideTuple().ClientAddress)
			srcport = mess.Session.GetClientSideTuple().ServerPort
			dstport = mess.Session.GetClientSideTuple().ClientPort
		}
	} else {
		logger.Err("Unsupported protocol for %d\n", mess.Session.GetConntrackID())
		return ""
	}

	// if we have a TCP layer update with the ports we saved above
	tcpPtr := fixer.Layer(layers.LayerTypeTCP)
	if tcpPtr != nil {
		TCPlayer := tcpPtr.(*layers.TCP)
		TCPlayer.SrcPort = layers.TCPPort(srcport)
		TCPlayer.DstPort = layers.TCPPort(dstport)
	}

	// if we have a UDP layer update with the ports we saved above
	udpPtr := mess.Packet.Layer(layers.LayerTypeUDP)
	if udpPtr != nil {
		UDPlayer := udpPtr.(*layers.UDP)
		UDPlayer.SrcPort = layers.UDPPort(srcport)
		UDPlayer.DstPort = layers.UDPPort(dstport)
	}

	// send the packet to the daemon for classification
	command = fmt.Sprintf("PACKET|%d|%s|%d\r\n", mess.Session.GetSessionID(), proto, len(fixer.Data()))
	reply = daemonClassifyPacket(command, fixer.Data())
	return reply
}

// processReply processes a reply from the classd daemon
func processReply(reply string, mess dispatch.NfqueueMessage, ctid uint32) (int, int32) {
	var appid string
	var name string
	var protochain string
	var detail string
	var confidence int32
	var category string
	var productivity uint8
	var state int
	var risk uint8
	var attachments map[string]interface{}

	// parse update classd information from reply
	appid, name, protochain, detail, confidence, category, state, productivity, risk = parseReply(reply)

	// WARNING - DO NOT USE Session GetAttachment or SetAttachment in this function
	// Because we make decisions based on existing attachments and update multiple
	// attachments, we lock the attachments and access them directly for efficiency.
	// Other calls that lock the attachment mutex will hang forever if called from here.
	attachments = mess.Session.LockAttachments()
	defer mess.Session.UnlockAttachments()

	// We look at the confidence and ignore any reply where the value is less
	// than the confidence currently attached to the session. Because of the
	// unpredictable nature of gorouting scheduling, we sometimes get confidence = 0
	// if NAVL didn't give us any classification. This can happen if packets are
	// processed out of order and NAVL gets data for a session that has already
	// encountered a FIN packet. In this case it generates a no connection error
	// and classd gives us the generic /IP defaults. We also don't want to apply
	// a lower confidence reply on top of a higher confidence reply which can
	// happen if the lower confidence reply is received and parsed after the
	// higher confidence reply has already been handled.

	checkdata := attachments["application_confidence"]
	if checkdata != nil {
		checkval := checkdata.(int32)
		if confidence < checkval {
			logger.Debug("%OC|Ignoring update with confidence %d < %d STATE:%d\n", "classify_confidence_regression", 0, confidence, checkval, state)
			return state, confidence
		}
	}

	var changed []string
	if updateClassifyDetail(attachments, ctid, "application_id", appid) {
		changed = append(changed, "application_id")
	}
	if updateClassifyDetail(attachments, ctid, "application_name", name) {
		changed = append(changed, "application_name")
	}
	if updateClassifyDetail(attachments, ctid, "application_protochain", protochain) {
		changed = append(changed, "application_protochain")
	}
	if updateClassifyDetail(attachments, ctid, "application_detail", detail) {
		changed = append(changed, "application_detail")
	}
	if updateClassifyDetail(attachments, ctid, "application_confidence", confidence) {
		changed = append(changed, "application_confidence")
	}
	if updateClassifyDetail(attachments, ctid, "application_category", category) {
		changed = append(changed, "application_category")
	}
	if updateClassifyDetail(attachments, ctid, "application_productivity", productivity) {
		changed = append(changed, "application_productivity")
	}
	if updateClassifyDetail(attachments, ctid, "application_risk", risk) {
		changed = append(changed, "application_risk")
	}

	// if something changed, log a new event
	if len(changed) > 0 {
		logEvent(mess.Session, attachments, changed)
	}

	return state, confidence
}

// parseReply parses a reply from classd and returns
// (appid, name, protochain, detail, confidence, category, state)
func parseReply(replyString string) (string, string, string, string, int32, string, int, uint8, uint8) {
	var err error
	var appid string
	var name string
	var protochain string
	var detail string
	var confidence int32
	var conparse uint64
	var category string
	var productivity uint8
	var state int
	var risk uint8

	rawinfo := strings.Split(replyString, "\r\n")

	for i := 0; i < len(rawinfo); i++ {
		if len(rawinfo[i]) < 3 {
			continue
		}
		rawpair := strings.SplitAfter(rawinfo[i], ": ")
		if len(rawpair) != 2 {
			continue
		}

		switch rawpair[0] {
		case "APPLICATION: ":
			appid = rawpair[1]
		case "PROTOCHAIN: ":
			protochain = rawpair[1]
		case "DETAIL: ":
			detail = rawpair[1]
		case "CONFIDENCE: ":
			conparse, err = strconv.ParseUint(rawpair[1], 10, 32)
			if err != nil {
				confidence = 0
			} else {
				confidence = int32(conparse)
			}
		case "STATE: ":
			state, err = strconv.Atoi(rawpair[1])
			if err != nil {
				state = 0
			}
		}
	}

	// lookup the category in the application table
	appinfo, finder := appclassmanager.ApplicationTable[appid]
	if finder == true {
		name = appinfo.Name
		category = appinfo.Category
		productivity = appinfo.Productivity
		risk = appinfo.Risk
	}

	return appid, name, protochain, detail, confidence, category, state, productivity, risk

}

// analyzePrection compares the actual classification details with those
// determined by the prediction plugin. If different the actual details
// are added to a list that will be pushed to the cloud.
func analyzePrediction(session *dispatch.Session) {
	matchAppid := session.GetAttachment("application_id")
	// if match not found just return
	if matchAppid == nil {
		return
	}

	inferAppid := session.GetAttachment("application_id_inferred")
	// if we have infer and match and infer are the same just return
	if inferAppid != nil && strings.Compare(matchAppid.(string), inferAppid.(string)) == 0 {
		return
	}

	// match and infer are different so queue the details for cloud submission
	logger.Debug("%OC|SESSION:%v inferAppid(%v) != matchAppid(%v) - adding to cloud report\n", "classify_match_infer_mismatch", 0, session.GetSessionID(), inferAppid, matchAppid)

	report := new(cloudReport)
	report.Protocol = session.GetClientSideTuple().Protocol
	report.ServerAddr = fmt.Sprintf("%v", session.GetClientSideTuple().ServerAddress)
	report.ServerPort = session.GetClientSideTuple().ServerPort

	if ptr := session.GetAttachment("application_id"); ptr != nil {
		report.Application = ptr.(string)
	}

	if ptr := session.GetAttachment("application_protochain"); ptr != nil {
		report.Protochain = ptr.(string)
	}

	if ptr := session.GetAttachment("application_detail"); ptr != nil {
		report.Detail = ptr.(string)
	}

	storeCloudReport(report)
}

// logEvent logs a session_classify event that updates the application_* columns
// provide the session and the changed column names
func logEvent(session *dispatch.Session, attachments map[string]interface{}, changed []string) {
	if len(changed) == 0 {
		return
	}
	columns := map[string]interface{}{
		"session_id": session.GetSessionID(),
	}
	modifiedColumns := make(map[string]interface{})
	for _, v := range changed {
		modifiedColumns[v] = attachments[v]
	}

	reports.LogEvent(reports.CreateEvent("session_classify", "sessions", 2, columns, modifiedColumns))
}

// updateClassifyDetail updates a key/value pair in the session attachments
// if the value has changed for the provided key, it will also update the nf_dict session table
// returns true if value changed, false otherwise
func updateClassifyDetail(attachments map[string]interface{}, ctid uint32, pairname string, pairdata interface{}) bool {

	// we don't wan't to put empty strings in the attachments or the dictionary
	switch v := pairdata.(type) {
	case string:
		if len(v) > 0 {
			break
		}
		logger.Trace("Empty classification detail for %s\n", pairname)
		return false
	}

	// if the session doesn't have this attachment yet we add it and write to the dictionary
	checkdata := attachments[pairname]
	if checkdata == nil {
		attachments[pairname] = pairdata
		dict.AddSessionEntry(ctid, pairname, pairdata)
		logger.Debug("Setting classification detail %s = %v ctid:%d\n", pairname, pairdata, ctid)
		return true
	}

	// if the session has the attachment and it has not changed just return
	if checkdata == pairdata {
		if logger.IsTraceEnabled() {
			logger.Trace("Ignoring classification detail %s = %v ctid:%d\n", pairname, pairdata, ctid)
		}
		return false
	}

	// at this point the session has the attachment but the data has changed so we update the session and the dictionary
	attachments[pairname] = pairdata
	dict.AddSessionEntry(ctid, pairname, pairdata)
	logger.Debug("Updating classification detail %s from %v to %v ctid:%d\n", pairname, checkdata, pairdata, ctid)
	return true
}

// SetHostPort sets the address for the classdDaemon. Default is "127.0.0.1:8123"
func SetHostPort(value string) {
	classdHostPort = value
}

// signalProcessManager sends a signal to the daemon manager goroutine
func signalProcessManager(signal daemonSignal) {
	select {
	case processChannel <- signal:
	default:
	}
}

func signalSocketManager(signal daemonSignal) {
	select {
	case socketChannel <- signal:
	default:
	}
}

func signalCloudManager(signal daemonSignal) {
	select {
	case cloudChannel <- signal:
	default:
	}
}
