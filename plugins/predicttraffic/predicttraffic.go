package predicttraffic

import (
	"github.com/untangle/packetd/services/dispatch"
	"github.com/untangle/packetd/services/logger"
	"github.com/untangle/packetd/services/predicttrafficsvc"
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

	predicttrafficsvc.GetTrafficClassification(ctid, mess.MsgTuple.ServerAddress, mess.MsgTuple.ServerPort, mess.MsgTuple.Protocol)

	return result
}
