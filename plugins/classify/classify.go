package classify

import (
	"fmt"
	"github.com/untangle/packetd/services/conndict"
	"github.com/untangle/packetd/services/support"
	"net"
	"strings"
	"sync"
	"time"
)

var socktime time.Time
var sockspin int64
var appname = "classify"
var daemon net.Conn

var classdHostPort string

//-----------------------------------------------------------------------------

// PluginStartup is called to allow plugin specific initialization. We
// increment the argumented WaitGroup so the main process can wait for
// our goodbye function to return during shutdown.
func PluginStartup(childsync *sync.WaitGroup, classdPtr *string) {
	var err error

	classdHostPort = *classdPtr

	support.LogMessage(support.LogInfo, appname, "PluginStartup(%s) has been called\n", appname)

	support.SystemCommand("systemctl", []string{"start", "untangle-classd.service"})

	socktime = time.Now()
	sockspin = 0
	daemon, err = net.Dial("tcp", classdHostPort)

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
	support.LogMessage(support.LogInfo, appname, "PluginGoodbye(%s) has been called\n", appname)

	if daemon != nil {
		daemon.Close()
	}

	childsync.Done()
}

//-----------------------------------------------------------------------------

// PluginNetfilterHandler is called for raw netfilter packets. We pass the
// packet directly to the Sandvine NAVL library for classification, and
// push the results to the conntrack dictionary.
func PluginNetfilterHandler(ch chan<- support.SubscriptionResult, mess support.TrafficMessage, ctid uint) {
	var result support.SubscriptionResult
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
		status, err = daemonCommand(nil, "CREATE:%d:%s:%s:%d:%s:%d\r\n", ctid, proto, mess.Session.SessionTuple.ClientAddr, mess.Session.SessionTuple.ClientPort, mess.Session.SessionTuple.ServerAddr, mess.Session.SessionTuple.ServerPort)
		if err != nil {
			support.LogMessage(support.LogErr, appname, "daemonCommand error: %s\n", err.Error())
			ch <- result
			return
		}
		support.LogMessage(support.LogLogic, appname, "daemonCommand result: %s\n", status)
	}

	// send the application payload to the daemon
	if mess.Session.SessionTuple.ClientAddr.Equal(mess.IPlayer.SrcIP) {
		status, err = daemonCommand(mess.Payload, "CLIENT:%d:%d\r\n", ctid, len(mess.Payload))
	} else {
		status, err = daemonCommand(mess.Payload, "SERVER:%d:%d\r\n", ctid, len(mess.Payload))
	}

	if err != nil {
		support.LogMessage(support.LogErr, appname, "daemonCommand error: %s\n", err.Error())
		ch <- result
		return
	}

	support.LogMessage(support.LogLogic, appname, "daemonCommand result: %s\n", status)

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

		ret := conndict.SetPair(pairname, pairdata, ctid)
		if ret != nil {
			support.LogMessage(support.LogWarn, appname, "SetPair(%s,%s,%d) ERROR: %s\n", pairname, pairdata, ctid, ret)
		} else {
			support.LogMessage(support.LogDebug, appname, "SetPair(%s,%s,%d) SUCCESS\n", pairname, pairdata, ctid)
		}
	}

	// use the channel to return our result
	ch <- result
}

//-----------------------------------------------------------------------------

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

//-----------------------------------------------------------------------------
