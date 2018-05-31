package classify

import (
	"fmt"
	"github.com/untangle/packetd/conndict"
	"github.com/untangle/packetd/support"
	"net"
	"strings"
	"sync"
)

var appname = "classify"
var daemon net.Conn

//-----------------------------------------------------------------------------

// PluginStartup is called to allow plugin specific initialization. We
// increment the argumented WaitGroup so the main process can wait for
// our goodbye function to return during shutdown.
func PluginStartup(childsync *sync.WaitGroup) {
	var err error
	support.LogMessage(support.LogInfo, appname, "PluginStartup(%s) has been called\n", "classify")

	daemon, err = net.Dial("tcp", "127.0.0.1:8123")

	if err != nil {
		support.LogMessage(support.LogErr, appname, "Error calling net.Dial(): %v\n", err)
	}

	support.InsertNetfilterSubscription(appname, 1, PluginNetfilterHandler)
	childsync.Add(1)
}

//-----------------------------------------------------------------------------

// PluginGoodbye is called when the daemon is shutting down. We call Done
// for the argumented WaitGroup to let the main process know we're finished.
func PluginGoodbye(childsync *sync.WaitGroup) {
	support.LogMessage(support.LogInfo, appname, "PluginGoodbye(%s) has been called\n", "classify")
	daemon.Close()
	childsync.Done()
}

//-----------------------------------------------------------------------------

// PluginNetfilterHandler is called for raw netfilter packets. We pass the
// packet directly to the Sandvine NAVL library for classification, and
// push the results to the conntrack dictionary.
func PluginNetfilterHandler(ch chan<- support.SubscriptionResult, mess support.TrafficMessage, ctid uint) {
	var status string
	var proto string

	if mess.MsgUDP != nil {
		proto = "UDP"
	}
	if mess.MsgTCP != nil {
		proto = "TCP"
	}

	// if this is the first packet of the session we send a session create command
	if mess.MsgSession.UpdateCount == 1 {
		status = daemonCommand(nil, "CREATE:%d:%s:%s:%d:%s:%d\r\n", ctid, proto, mess.MsgSession.SessionTuple.ClientAddr, mess.MsgSession.SessionTuple.ClientPort, mess.MsgSession.SessionTuple.ServerAddr, mess.MsgSession.SessionTuple.ServerPort)
		support.LogMessage(support.LogDebug, appname, "daemonCommand result: %s\n", status)
	}

	// send the application payload to the daemon
	if mess.MsgSession.SessionTuple.ClientAddr.Equal(mess.MsgIP.SrcIP) {
		status = daemonCommand(mess.Payload, "CLIENT:%d:%d\r\n", ctid, len(mess.Payload))
	} else {
		status = daemonCommand(mess.Payload, "SERVER:%d:%d\r\n", ctid, len(mess.Payload))
	}

	// Parse the output from classd to get the classification details
	var pairname string
	var pairdata string
	var pairflag bool

	catinfo := strings.Split(status, "\r\n")

	for i := 0; i < len(catinfo); i++ {
		if len(catinfo[i]) < 3 {
			continue
		}
		catpair := strings.SplitAfter(catinfo[i], ": ")
		if len(catpair) != 2 {
			continue
		}

		pairflag = false

		if catpair[0] == "APPLICATION: " {
			pairname = "ClassifyApplication"
			pairdata = catpair[1]
			pairflag = true
		}

		if catpair[0] == "PROTOCHAIN: " {
			pairname = "ClassifyProtochain"
			pairdata = catpair[1]
			pairflag = true
		}

		if catpair[0] == "DETAIL: " {
			pairname = "ClassifyDetail"
			pairdata = catpair[1]
			pairflag = true
		}

		if catpair[0] == "CONFIDENCE: " {
			pairname = "ClassifyConfidence"
			pairdata = catpair[1]
			pairflag = true
		}

		if catpair[0] == "STATE: " {
			pairname = "ClassifyState"
			pairdata = catpair[1]
			pairflag = true
		}

		if pairflag == false {
			continue
		}

		err := conndict.SetPair(pairname, pairdata, ctid)
		if err != nil {
			support.LogMessage(support.LogWarning, appname, "SetPair(%s,%s,%d) ERROR: %s\n", pairname, pairdata, ctid, err)
		} else {
			support.LogMessage(support.LogDebug, appname, "SetPair(%s,%s,%d) SUCCESS\n", pairname, pairdata, ctid)
		}
	}

	var result support.SubscriptionResult
	result.Owner = appname
	result.PacketMark = 0
	result.SessionRelease = false

	// use the channel to return our result
	ch <- result
}

//-----------------------------------------------------------------------------

// daemonCommand will send a command to the untangle-classd daemon and return the result message
func daemonCommand(rawdata []byte, format string, args ...interface{}) string {

	// TODO - need to add timeout, reconnect, rx and tx buffering, and other exception detection and handling here

	buffer := make([]byte, 1024)
	var command string
	var err error
	var tot int

	// if there are no arguments use the format as the command otherwise create command from the arguments
	if len(args) == 0 {
		command = format
	} else {
		command = fmt.Sprintf(format, args...)
	}

	// write the command to the daemon socket
	tot, err = daemon.Write([]byte(command))

	if err != nil {
		support.LogMessage(support.LogErr, appname, "Error calling daemon.Write(%s): %v\n", command, err)
		return (string(buffer))
	}

	if tot != len(command) {
		support.LogMessage(support.LogErr, appname, "Underrun %d of %d calling daemon.Write(%s)\n", tot, len(command), command)
		return (string(buffer))
	}

	// if we have raw payload data send to the daemon socket after the command
	if rawdata != nil {
		tot, err = daemon.Write(rawdata)

		if err != nil {
			support.LogMessage(support.LogErr, appname, "Error calling daemon.Write(): %v\n", err)
			return (string(buffer))
		}

		if tot != len(rawdata) {
			support.LogMessage(support.LogErr, appname, "Write could only send %d of %d rawdata bytes\n", tot, len(rawdata))
			return (string(buffer))
		}

	}

	// read the response from the daemon
	tot, err = daemon.Read(buffer)

	if err != nil {
		support.LogMessage(support.LogErr, appname, "Error calling daemon.Read(): %v\n", err)
	}

	return (string(buffer))
}

//-----------------------------------------------------------------------------
