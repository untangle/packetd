package predicttraffic

import (
	"github.com/untangle/packetd/services/dict"
	"github.com/untangle/packetd/services/dispatch"
	"github.com/untangle/packetd/services/logger"
	"github.com/untangle/packetd/services/predicttrafficsvc"
	"github.com/untangle/packetd/services/reports"
)

const pluginName = "predicttraffic"

// PluginStartup function is called to allow plugin specific initialization. We
// increment the argumented WaitGroup so the main process can wait for
// our shutdown function to return during shutdown.
func PluginStartup() {
	logger.Info("PluginStartup(%s) has been called\n", pluginName)
	dispatch.InsertNfqueueSubscription(pluginName, dispatch.ExamplePriority, PluginNfqueueHandler)
}

// PluginShutdown function called when the daemon is shutting down. We call Done
// for the argumented WaitGroup to let the main process know we're finished.
func PluginShutdown() {
	logger.Info("PluginShutdown(%s) has been called\n", pluginName)
}

// PluginNfqueueHandler receives a NfqueueMessage which includes a Tuple and
// a gopacket.Packet, along with the IP and TCP or UDP layer already extracted.
// We do whatever we like with the data, and when finished, we return an
// integer via the argumented channel with any bits set that we want added to
// the packet mark.
func PluginNfqueueHandler(mess dispatch.NfqueueMessage, ctid uint32, newSession bool) dispatch.NfqueueResult {

	//Currently this releases but we need to block on the first packet
	var result dispatch.NfqueueResult
	dispatch.ReleaseSession(mess.Session, pluginName)

	//Tell service to cache and categorize this ip request
	logger.Debug("Running traffic classification on request: Client address: %s, client port: %d, Server address: %s, Server port: %d, Protocol: %d,  \n", mess.MsgTuple.ClientAddress, mess.MsgTuple.ClientPort, mess.MsgTuple.ServerAddress, mess.MsgTuple.ServerPort, mess.MsgTuple.Protocol)

	var trafficInfo = predicttrafficsvc.GetTrafficClassification(mess.MsgTuple.ServerAddress, mess.MsgTuple.ServerPort, mess.MsgTuple.Protocol)

	if trafficInfo != nil {
		addPredictionToDict(ctid, trafficInfo)
		addPredictionToReport(mess, trafficInfo)
		addPredictionToSession(mess.Session, trafficInfo)
	}

	return result
}

// addPredictionToDict will take a ClassifiedTraffic pointer and send the data to dict
func addPredictionToDict(ctid uint32, currentTraffic *predicttrafficsvc.ClassifiedTraffic) {
	logger.Debug("Sending prediction info to dict with ctid: %d\n", ctid)
	dict.AddSessionEntry(ctid, "application_id_inferred", currentTraffic.ID)
	dict.AddSessionEntry(ctid, "application_name_inferred", currentTraffic.Name)
	dict.AddSessionEntry(ctid, "application_confidence_inferred", roundConfidence(currentTraffic.Confidence))
	dict.AddSessionEntry(ctid, "application_protochain_inferred", currentTraffic.ProtoChain)
	dict.AddSessionEntry(ctid, "application_productivity_inferred", currentTraffic.Productivity)
	dict.AddSessionEntry(ctid, "application_risk_inferred", currentTraffic.Risk)
	dict.AddSessionEntry(ctid, "application_category_inferred", currentTraffic.Category)

}

// addPredictionToReport will take a ClassifiedTraffic pointer and send the data into the reports sqlite database, under the sessions table
func addPredictionToReport(mess dispatch.NfqueueMessage, currentTraffic *predicttrafficsvc.ClassifiedTraffic) {
	logger.Debug("Sending prediction info to sessions table: %d\n", mess.Session.GetSessionID())

	columns := map[string]interface{}{
		"session_id": mess.Session.GetSessionID(),
	}

	modifiedColumns := make(map[string]interface{})
	modifiedColumns["application_id_inferred"] = currentTraffic.ID
	modifiedColumns["application_name_inferred"] = currentTraffic.Name
	modifiedColumns["application_confidence_inferred"] = roundConfidence(currentTraffic.Confidence)
	modifiedColumns["application_protochain_inferred"] = currentTraffic.ProtoChain
	modifiedColumns["application_productivity_inferred"] = currentTraffic.Productivity
	modifiedColumns["application_risk_inferred"] = currentTraffic.Risk
	modifiedColumns["application_category_inferred"] = currentTraffic.Category

	reports.LogEvent(reports.CreateEvent("session_predict_traffic", "sessions", 2, columns, modifiedColumns))
}

// addPredictionToDict will take a ClassifiedTraffic pointer and send the data to dict
func addPredictionToSession(session *dispatch.Session, currentTraffic *predicttrafficsvc.ClassifiedTraffic) {
	logger.Debug("Sending prediction info to session attachments: %d\n", session.GetSessionID())
	session.PutAttachment("application_id_inferred", currentTraffic.ID)
	session.PutAttachment("application_name_inferred", currentTraffic.Name)
	session.PutAttachment("application_confidence_inferred", roundConfidence(currentTraffic.Confidence))
	session.PutAttachment("application_protochain_inferred", currentTraffic.ProtoChain)
	session.PutAttachment("application_productivity_inferred", currentTraffic.Productivity)
	session.PutAttachment("application_risk_inferred", currentTraffic.Risk)
	session.PutAttachment("application_category_inferred", currentTraffic.Category)
}

// round confidence converts the confidence from a float32 into a uint8, with very basic logic to round up or down
func roundConfidence(conf float32) uint8 {
	if conf < 0 {
		return uint8(conf - 0.5)
	}
	return uint8(conf + 0.5)
}
