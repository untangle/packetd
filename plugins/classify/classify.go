package classify

import (
	"fmt"
	"github.com/untangle/packetd/services/conndict"
	"github.com/untangle/packetd/services/dispatch"
	"github.com/untangle/packetd/services/exec"
	"github.com/untangle/packetd/services/logger"
	"net"
	"strings"
	"time"
)

var socktime time.Time
var sockspin int64
var appname = "classify"
var daemon net.Conn
var classdHostPort = "127.0.0.1:8123"

// PluginStartup is called to allow plugin specific initialization. We
// increment the argumented WaitGroup so the main process can wait for
// our shutdown function to return during shutdown.
func PluginStartup() {
	var err error

	logger.LogMessage(logger.LogInfo, appname, "PluginStartup(%s) has been called\n", appname)

	exec.SystemCommand("systemctl", []string{"start", "untangle-classd.service"})

	socktime = time.Now()
	sockspin = 0
	daemon, err = net.Dial("tcp", classdHostPort)

	if err != nil {
		logger.LogMessage(logger.LogErr, appname, "Error calling net.Dial(): %v\n", err)
	}

	dispatch.InsertNfqueueSubscription(appname, 2, PluginNfqueueHandler)
}

// PluginShutdown is called when the daemon is shutting down. We call Done
// for the argumented WaitGroup to let the main process know we're finished.
func PluginShutdown() {
	logger.LogMessage(logger.LogInfo, appname, "PluginShutdown(%s) has been called\n", appname)

	if daemon != nil {
		daemon.Close()
	}
}

// SetHostPort sets the address for the classdDaemon. Default is "127.0.0.1:8123"
func SetHostPort(value string) {
	classdHostPort = value
}

// PluginNfqueueHandler is called for raw nfqueue packets. We pass the
// packet directly to the Sandvine NAVL library for classification, and
// push the results to the conntrack dictionary.
func PluginNfqueueHandler(mess dispatch.TrafficMessage, ctid uint, newSession bool) dispatch.NfqueueResult {
	var result dispatch.NfqueueResult
	result.Owner = appname
	result.PacketMark = 0
	result.SessionRelease = false

	var status string
	var proto string
	var err error

	if mess.UDPlayer != nil {
		proto = "UDP"
	}
	if mess.TCPlayer != nil {
		proto = "TCP"
	}

	// if this is the first packet of the session we send a session create command
	if mess.Session.UpdateCount == 1 {
		status, err = daemonCommand(nil, "CREATE:%d:%s:%s:%d:%s:%d\r\n", ctid, proto, mess.Session.ClientSideTuple.ClientAddr, mess.Session.ClientSideTuple.ClientPort, mess.Session.ClientSideTuple.ServerAddr, mess.Session.ClientSideTuple.ServerPort)
		if err != nil {
			logger.LogMessage(logger.LogErr, appname, "daemonCommand error: %s\n", err.Error())
			return result
		}
		logger.LogMessage(logger.LogTrace, appname, "daemonCommand result: %s\n", status)
	}

	// send the application payload to the daemon
	if mess.Session.ClientSideTuple.ClientAddr.Equal(mess.IPlayer.SrcIP) {
		status, err = daemonCommand(mess.Payload, "CLIENT:%d:%d\r\n", ctid, len(mess.Payload))
	} else {
		status, err = daemonCommand(mess.Payload, "SERVER:%d:%d\r\n", ctid, len(mess.Payload))
	}

	if err != nil {
		logger.LogMessage(logger.LogErr, appname, "daemonCommand error: %s\n", err.Error())
		return result
	}

	logger.LogMessage(logger.LogTrace, appname, "daemonCommand result: %s\n", status)

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

		// continue if the tag is something we don't want
		if pairflag == false {
			continue
		}

		// continue if the tag has no data
		if len(pairdata) == 0 {
			continue
		}

		conndict.SetPair(pairname, pairdata, ctid)
	}

	return result
}

// daemonCommand will send a command to the untangle-classd daemon and return the result message
func daemonCommand(rawdata []byte, format string, args ...interface{}) (string, error) {
	buffer := make([]byte, 1024)
	var command string
	var err error
	var tot int

	// if daemon not connected we do throttled reconnect attempts
	if daemon == nil {
		nowtime := time.Now()

		// if not time for another attempt return lost connection error
		if (socktime.Unix() + sockspin) > nowtime.Unix() {
			return string(buffer), fmt.Errorf("Lost connection to daemon. Reconnect in %d seconds", sockspin)
		}

		// update socktime and try to connect to the daemon
		socktime = time.Now()
		daemon, err = net.Dial("tcp", classdHostPort)
		if err != nil {
			// if the connection failed update the throttle counter and return the error
			if sockspin < 10 {
				sockspin++
			}
			return string(buffer), err
		}
	}

	// on successful connect update the socktime and clear the throttle counter
	socktime = time.Now()
	sockspin = 0

	// if there are no arguments use the format as the command otherwise create command from the arguments
	if len(args) == 0 {
		command = format
	} else {
		command = fmt.Sprintf(format, args...)
	}

	// write the command to the daemon socket
	tot, err = daemon.Write([]byte(command))

	if err != nil {
		daemon.Close()
		daemon = nil
		return string(buffer), err
	}

	if tot != len(command) {
		daemon.Close()
		daemon = nil
		return string(buffer), fmt.Errorf("Underrun %d of %d calling daemon.Write(%s)", tot, len(command), command)
	}

	// if we have raw payload data send to the daemon socket after the command
	if rawdata != nil {
		tot, err = daemon.Write(rawdata)

		if err != nil {
			daemon.Close()
			daemon = nil
			return string(buffer), err
		}

		if tot != len(rawdata) {
			daemon.Close()
			daemon = nil
			return string(buffer), fmt.Errorf("Underrun %d of %d calling daemon.Write(rawdata)", tot, len(rawdata))
		}

	}

	// read the response from the daemon
	tot, err = daemon.Read(buffer)

	if err != nil {
		daemon.Close()
		daemon = nil
		return string(buffer), err
	}

	return string(buffer), nil
}
