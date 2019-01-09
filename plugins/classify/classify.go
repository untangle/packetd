// Package classify classifies sessions as certain applications
// each packet gets sent to a classd daemon (the categorization engine)
// the classd daemon returns the classification information and classify
// attaches the information to the session.
package classify

import (
	"bufio"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/untangle/packetd/services/dict"
	"github.com/untangle/packetd/services/dispatch"
	"github.com/untangle/packetd/services/logger"
	"github.com/untangle/packetd/services/reports"
)

// applicationInfo stores the details for each know application
type applicationInfo struct {
	guid         string
	index        int
	name         string
	description  string
	category     string
	productivity int
	risk         int
	flags        uint64
	reference    string
	plugin       string
}

const pluginName = "classify"
const daemonBinary = "/usr/bin/classd"
const guidInfoFile = "/usr/share/untangle-classd/protolist.csv"

const navlStateTerminated = 0 // Indicates the connection has been terminated
const navlStateInspecting = 1 // Indicates the connection is under inspection
const navlStateMonitoring = 2 // Indicates the connection is under monitoring
const navlStateClassified = 3 // Indicates the connection is fully classified

const maxPacketCount = 32     // The maximum number of packets to inspect before releasing
const maxTrafficSize = 0x8000 // The maximum number of bytes to inspect before releasing

var applicationTable map[string]applicationInfo
var shutdownFlag = false
var daemonProcess *exec.Cmd
var daemonSocket net.Conn
var daemonChannel = make(chan bool, 1)

var classdHostPort = "127.0.0.1:8123"
var classdMutex sync.Mutex
var dialCounter int

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

	loadApplicationTable()

	// start the daemon manager to handle running the daemon and connecting the socket
	go daemonManager()

	// insert our nfqueue and conntrack subscriptions
	dispatch.InsertNfqueueSubscription(pluginName, 2, PluginNfqueueHandler)
}

// PluginShutdown is called when the daemon is shutting down
func PluginShutdown() {
	logger.Info("PluginShutdown(%s) has been called\n", pluginName)

	// first signal the shutdown channel to stop the daemon manager
	shutdownFlag = true
	daemonChannel <- true

	select {
	case <-daemonChannel:
		logger.Info("Successful shutdown of daemonManager\n")
	case <-time.After(10 * time.Second):
		logger.Warn("Failed to properly shutdown daemonManager\n")
	}
}

// SetHostPort sets the address for the classdDaemon. Default is "127.0.0.1:8123"
func SetHostPort(value string) {
	classdHostPort = value
}

// PluginNfqueueHandler is called for raw nfqueue packets. We pass the
// packet directly to the Sandvine NAVL library for classification, and
// push the results to the conntrack dictionary.
func PluginNfqueueHandler(mess dispatch.NfqueueMessage, ctid uint32, newSession bool) dispatch.NfqueueResult {
	var reply string
	var err error

	// make sure we have a valid session
	if mess.Session == nil {
		logger.Err("Ignoring event with invalid Session\n")
		return dispatch.NfqueueResult{SessionRelease: true}
	}

	// make sure we have a valid conntrack id
	if mess.Session.SessionID == 0 {
		logger.Err("Ignoring event with invalid SessionID\n")
		return dispatch.NfqueueResult{SessionRelease: true}
	}

	// make sure we have a valid IPv4 or IPv6 layer
	if mess.IP4Layer == nil && mess.IP6Layer == nil {
		logger.Err("Invalid packet: %v\n", mess.Session.ClientSideTuple.Protocol)
		return dispatch.NfqueueResult{SessionRelease: true}
	}

	// if not connected to the daemon we can't do anything
	if daemonSocket == nil {
		logger.Warn("Connection to classd failed. Restarting classd...\n")
		// write to daemonChannel, but don't block
		select {
		case daemonChannel <- true:
		default:
		}
		// Release this session just in case
		// If this is happening something is wrong
		// While releasing is not ideal, its better if the daemon
		// has crashed and can't be brought back
		return dispatch.NfqueueResult{SessionRelease: true}
	}

	// send the data to classd and read reply
	reply, err = daemonClassify(mess, mess.Session.SessionID, newSession)
	if err != nil {
		logger.Err("classd communication error: %v\n", err)
		return dispatch.NfqueueResult{SessionRelease: true}
	}

	// process the reply and get the classification state
	state := processReply(reply, mess, ctid)

	// if the daemon says the session is fully classified or terminated, or after we have seen maximum packets or data, release the session
	if state == navlStateClassified || state == navlStateTerminated || mess.Session.PacketCount > maxPacketCount || mess.Session.ByteCount > maxTrafficSize {
		return dispatch.NfqueueResult{SessionRelease: true}
	}

	return dispatch.NfqueueResult{SessionRelease: false}
}

// daemonClassify sends classd the commands and returns the reply
func daemonClassify(mess dispatch.NfqueueMessage, sessionID uint64, newSession bool) (string, error) {
	var proto string
	var reply string
	var err error

	if mess.IP4Layer != nil {
		proto = "IP4"
	} else if mess.IP6Layer != nil {
		proto = "IP6"
	} else {
		return "", errors.New("Unsupported protocol")
	}

	// send the packet data to the daemon
	reply, err = daemonCommand(mess.Packet.Data(), "PACKET|%d|%s|%d\r\n", sessionID, proto, len(mess.Packet.Data()))

	if err != nil {
		logger.Err("daemonCommand error: %s\n", err.Error())
		return "", err
	}

	if logger.IsTraceEnabled() {
		logger.Trace("daemonCommand result: %s\n", strings.Replace(strings.Replace(reply, "\n", "|", -1), "\r", "", -1))
	}
	return reply, nil
}

// processReply processes a reply from the classd daemon
func processReply(reply string, mess dispatch.NfqueueMessage, ctid uint32) int {
	var appid string
	var name string
	var protochain string
	var detail string
	var confidence uint64
	var category string
	var state int

	// parse update classd information from reply
	appid, name, protochain, detail, confidence, category, state = parseReply(reply)

	var changed []string
	if updateClassifyDetail(mess, ctid, "application_id", appid) {
		changed = append(changed, "application_id")
	}
	if updateClassifyDetail(mess, ctid, "application_name", name) {
		changed = append(changed, "application_name")
	}
	if updateClassifyDetail(mess, ctid, "application_protochain", protochain) {
		changed = append(changed, "application_protochain")
	}
	if updateClassifyDetail(mess, ctid, "application_detail", detail) {
		changed = append(changed, "application_detail")
	}
	if updateClassifyDetail(mess, ctid, "application_confidence", confidence) {
		changed = append(changed, "application_confidence")
	}
	if updateClassifyDetail(mess, ctid, "application_category", category) {
		changed = append(changed, "application_category")
	}

	// if something changed, log a new event
	if len(changed) > 0 {
		logEvent(mess.Session, changed)
	}

	return state
}

// parseReply parses a reply from classd and returns
// (appid, name, protochain, detail, confidence, category, state)
func parseReply(replyString string) (string, string, string, string, uint64, string, int) {
	var err error
	var appid string
	var name string
	var protochain string
	var detail string
	var confidence uint64
	var category string
	var state int

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
			break
		case "PROTOCHAIN: ":
			protochain = rawpair[1]
			break
		case "DETAIL: ":
			detail = rawpair[1]
			break
		case "CONFIDENCE: ":
			confidence, err = strconv.ParseUint(rawpair[1], 10, 64)
			if err != nil {
				confidence = 0
			}
			break
		case "STATE: ":
			state, err = strconv.Atoi(rawpair[1])
			if err != nil {
				state = 0
			}
			break
		}
	}

	// lookup the category in the application table
	appinfo, finder := applicationTable[appid]
	if finder == true {
		name = appinfo.name
		category = appinfo.category
	}

	return appid, name, protochain, detail, confidence, category, state

}

// logEvent logs a session_classify event that updates the application_* columns
// provide the session and the changed column names
func logEvent(session *dispatch.Session, changed []string) {
	if len(changed) == 0 {
		return
	}
	columns := map[string]interface{}{
		"session_id": session.SessionID,
	}
	modifiedColumns := make(map[string]interface{})
	for _, v := range changed {
		modifiedColumns[v] = session.GetAttachment(v)
	}

	reports.LogEvent(reports.CreateEvent("session_classify", "sessions", 2, columns, modifiedColumns))
}

// daemonCommand will send a command to the untangle-classd daemon and return the result message
func daemonCommand(rawdata []byte, format string, args ...interface{}) (string, error) {
	buffer := make([]byte, 1024)
	var command string
	var err error
	var tot int

	classdMutex.Lock()
	defer classdMutex.Unlock()

	// if daemon not connected we can't do anything
	if daemonSocket == nil {
		return "", fmt.Errorf("Connction to classify daemon not established")
	}

	// if there are no arguments use the format as the command otherwise create command from the arguments
	if len(args) == 0 {
		command = format
	} else {
		command = fmt.Sprintf(format, args...)
	}

	// write the command to the daemon socket
	tot, err = daemonSocket.Write([]byte(command))

	// on write error shutdown the socket and return error
	if err != nil {
		daemonGoodbye()
		return string(buffer), err
	}

	// on short write shutdown the socket and return error
	if tot != len(command) {
		daemonGoodbye()
		return string(buffer), fmt.Errorf("Underrun %d of %d calling daemon.Write(%s)", tot, len(command), command)
	}

	// if we have packet data send to the daemon socket after the command
	if rawdata != nil {
		tot, err = daemonSocket.Write(rawdata)

		// on write error shutdown the socket and return error
		if err != nil {
			daemonGoodbye()
			return string(buffer), err
		}

		// on short write shutdown the socket and return error
		if tot != len(rawdata) {
			daemonGoodbye()
			return string(buffer), fmt.Errorf("Underrun %d of %d calling daemon.Write(rawdata)", tot, len(rawdata))
		}
	}

	// read the reply from the daemon
	_, err = daemonSocket.Read(buffer)

	// on read error shutdown the socket and return error
	if err != nil {
		daemonGoodbye()
		return string(buffer), err
	}

	return string(buffer), nil
}

// loadApplicationTable loads the details for each application
func loadApplicationTable() {
	var file *os.File
	var linecount int
	var infocount int
	var list []string
	var err error

	applicationTable = make(map[string]applicationInfo)

	// open the guid info file provided by Sandvine
	file, err = os.Open(guidInfoFile)

	// if there was an error log and return
	if err != nil {
		logger.Warn("Unable to load application details: %s\n", guidInfoFile)
		return
	}

	// create a new CSV reader
	reader := csv.NewReader(bufio.NewReader(file))
	for {
		list, err = reader.Read()
		// on end of file just break out of the read loop
		if err == io.EOF {
			break
			// for anything else log the error and break
		} else if err != nil {
			logger.Err("Unable to parse application details: %v\n", err)
			break
		}

		// count the number of lines read so we can compare with
		// the number successfully parsed when we finish loading
		linecount++

		// skip the first line that holds the file format description
		if linecount == 1 {
			continue
		}

		// if we did not parse exactly 10 fields skip the line
		if len(list) != 10 {
			logger.Warn("Invalid line length: %d\n", len(list))
			continue
		}

		var info applicationInfo

		info.guid = list[0]
		info.index, err = strconv.Atoi(list[1])
		if err != nil {
			logger.Warn("Invalid index: %s\n", list[1])
		}
		info.name = list[2]
		info.description = list[3]
		info.category = list[4]
		info.productivity, err = strconv.Atoi(list[5])
		if err != nil {
			logger.Warn("Invalid productivity: %s\n", list[5])
		}
		info.risk, err = strconv.Atoi(list[6])
		if err != nil {
			logger.Warn("Invalid risk: %s\n", list[6])
		}
		info.flags, err = strconv.ParseUint(list[7], 10, 64)
		if err != nil {
			logger.Warn("Invalid flags: %s %s\n", list[7], err)
		}
		info.reference = list[8]
		info.plugin = list[9]

		applicationTable[list[0]] = info
		infocount++
	}

	file.Close()
	logger.Info("Loaded classification details for %d applications\n", infocount)

	// if there were any bad lines in the file log a warning
	if infocount != linecount-1 {
		logger.Warn("Detected garbage in the application info file: %s\n", guidInfoFile)
	}
}

// updateClassifyDetail updates a key/value pair in the session attachments
// if the value has changed for the provided key, it will also update the nf_dict session table
// returns true if value changed, false otherwise
func updateClassifyDetail(mess dispatch.NfqueueMessage, ctid uint32, pairname string, pairdata interface{}) bool {

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
	checkdata := mess.Session.GetAttachment(pairname)
	if checkdata == nil {
		mess.Session.PutAttachment(pairname, pairdata)
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
	mess.Session.PutAttachment(pairname, pairdata)
	dict.AddSessionEntry(ctid, pairname, pairdata)
	logger.Debug("Updating classification detail %s = %v ctid:%d\n", pairname, pairdata, ctid)
	return true
}

// daemonManager is a goroutine to start, connect, monitor, restart, and reconnect the untangle-classd daemon
// we also watch the shutdown channel and exit when the shutdown signal is received
func daemonManager() {
	daemonChannel <- true
	for {
		<-daemonChannel

		if shutdownFlag {
			daemonGoodbye()
			daemonShutdown()
			return
		}

		if daemonProcess == nil {
			daemonStartup()

			// Use a goroutine to wait for the process to finish. In normal operation Wait() will
			// return when the daemon shuts down in response to SIGINT which is sent after the
			// daemon manager has shutdown. If the daemon exits for any other reason the manager
			// will see the nil process and attempt to restart the daemon.
			go func() {
				err := daemonProcess.Wait()
				if err != nil {
					logger.Info("The classd daemon has exited. Error:%v\n", err)
				} else {
					logger.Info("The classd daemon has exited.\n")
				}
				daemonGoodbye()
				daemonProcess = nil
				daemonChannel <- true
			}()
		}
		if daemonSocket == nil {
			daemonConnect()
		}
		// sleep a bit to prevent spinning
		time.Sleep(500 * time.Millisecond)
	}
}

// starts the daemon and uses a goroutine to wait for it to finish
func daemonStartup() {
	var err error
	var daemonStdout io.ReadCloser
	var daemonStderr io.ReadCloser

	// start the classd daemon with the mfw flag to enable our mode of operation
	// include the local flag so we can capture the log output
	// include the debug flag when our own debug mode is enabled
	if logger.IsDebugEnabled() {
		daemonProcess = exec.Command(daemonBinary, "-mfw", "-l", "-d")
	} else {
		daemonProcess = exec.Command(daemonBinary, "-mfw", "-l")
	}

	// set a diffrent process group so it doesn't get packetd signals
	daemonProcess.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	// call the start function, check for error, and cleanup if things go bad
	_, err = daemonProcess.StdinPipe()
	if err != nil {
		logger.Err("Error starting classify daemon %s (%v)\n", daemonBinary, err)
		daemonProcess.Process.Release()
		daemonProcess = nil
		return
	}
	daemonStderr, err = daemonProcess.StderrPipe()
	if err != nil {
		logger.Err("Error starting classify daemon %s (%v)\n", daemonBinary, err)
		daemonProcess.Process.Release()
		daemonProcess = nil
		return
	}
	daemonStdout, err = daemonProcess.StdoutPipe()
	if err != nil {
		logger.Err("Error starting classify daemon %s (%v)\n", daemonBinary, err)
		daemonProcess.Process.Release()
		daemonProcess = nil
		return
	}
	err = daemonProcess.Start()
	if err != nil {
		logger.Err("Error starting classify daemon %s (%v)\n", daemonBinary, err)
		daemonProcess.Process.Release()
		daemonProcess = nil
		return
	}

	// Wait for startup to complete
	scanner := bufio.NewScanner(daemonStdout)
	for scanner.Scan() {
		// look for "starting" message
		txt := scanner.Text()
		logger.Info("classd: %v\n", txt)
		if strings.Contains(txt, "netserver thread is starting") {
			break
		}
	}

	printOutputFn := func(reader io.ReadCloser) {
		for {
			scanner := bufio.NewScanner(reader)
			for scanner.Scan() {
				logger.Info("classd: %v\n", scanner.Text())
			}
		}
	}
	go printOutputFn(daemonStdout)
	go printOutputFn(daemonStderr)

	logger.Info("The classd daemon has been started. PID:%d\n", daemonProcess.Process.Pid)
}

// called to send SIGINT to the classify daemon which will cause normal shutdown
func daemonShutdown() {
	if daemonProcess == nil {
		return
	}

	// signal an interrupt signal to the daemon
	err := daemonProcess.Process.Signal(os.Interrupt)
	if err != nil {
		logger.Err("Error stopping classd daemon: %v\n", err)
	} else {
		logger.Info("The classd daemon has been stopped\n")
	}

	daemonProcess = nil
}

func daemonConnect() {
	var err error

	// we can't connect if the daemon isn't running
	if daemonProcess == nil {
		return
	}

	// establish our connection to the daemon
	daemonSocket, err = net.DialTimeout("tcp", classdHostPort, 5*time.Second)
	if err != nil {
		logger.Err("Error calling net.DialTimeout(%s): %v\n", classdHostPort, err)
	} else {
		logger.Info("Succesfully connected to classify daemon(%s)\n", classdHostPort)
		dialCounter++
	}
}

// Called to shutdown the daemon connection. We close the connection if valid
// and clear the daemonSocket which will trigger the manager to reconnect
func daemonGoodbye() {
	if daemonSocket == nil {
		return
	}

	daemonSocket.Close()
	daemonSocket = nil
}
