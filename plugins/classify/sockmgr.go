// Package classify classifies sessions as certain applications
// each packet gets sent to a classd daemon (the categorization engine)
// the classd daemon returns the classification information and classify
// attaches the information to the session.
package classify

import (
	"net"
	"sync"
	"time"

	"github.com/untangle/packetd/services/logger"
)

var daemonSocket net.Conn
var daemonBuffer = make([]byte, 1024)
var socketMutex sync.Mutex

// daemonSocketManager is a goroutine to handle the daemon socket connection
func daemonSocketManager() {
	for {
		message := <-socketChannel

		// +++ socketConnect is sent to initiate the daemon socket connection
		if message == socketConnect {
			daemonSocketConnect()
		}

		// +++ systemShutdown is called from PluginShutdown when shutting down
		if message == systemShutdown {
			logger.Info("The daemonSocketManager is finished\n")
			daemonSocketClose()
			shutdownChannel <- true
			return
		}
	}
}

// daemonSocketConnect is called to establish the connection to the daemon
func daemonSocketConnect() {
	var err error

	socketMutex.Lock()
	defer socketMutex.Unlock()

	// if the socket is already connected we don't do anything
	if daemonSocket != nil {
		return
	}

	logger.Info("Attempting to connect to classify daemon(%s)\n", classdHostPort) // FIXME

	// establish our connection to the daemon
	daemonSocket, err = net.DialTimeout("tcp", classdHostPort, 2*time.Second)
	if err != nil {
		logger.Err("Error calling net.DialTimeout(%s): %v\n", classdHostPort, err)
		time.Sleep(time.Second)
		signalSocketManager(socketConnect)
		return
	}

	logger.Info("Successfully connected to classify daemon(%s)\n", classdHostPort)
}

// daemonSocketClose is called to close the daemon socket connection
func daemonSocketClose() {
	socketMutex.Lock()
	defer socketMutex.Unlock()

	if daemonSocket == nil {
		return
	}

	daemonSocket.Close()
	daemonSocket = nil
}

// daemonSocketReset is called when any socket send or receive error is detected
// we already hold the mutex so we close, clear, and send the signal to reconnect
func daemonSocketRecycle() {
	if daemonSocket != nil {
		daemonSocket.Close()
		daemonSocket = nil
	}
	signalSocketManager(socketConnect)
}

// daemonClassifyPacket sends data to the daemon for classification and returns the reply
func daemonClassifyPacket(command string, buffer []byte) string {
	var reply string
	var tot int
	var err error

	socketMutex.Lock()
	defer socketMutex.Unlock()

	// if the socket is nil we can't classify the data
	if daemonSocket == nil {
		return ""
	}

	logger.Trace("DAEMON COMMAND: %s\n", command)

	// write the command to the daemon socket
	daemonSocket.SetWriteDeadline(time.Now().Add(2 * time.Second))
	tot, err = daemonSocket.Write([]byte(command))

	// on write error recycle the socket connection and return empty result
	if err != nil {
		logger.Err("Error writing command to daemon socket: %v\n", err)
		daemonSocketRecycle()
		return ""
	}

	// on short write recycle the socket connection and return empty result
	if tot != len(command) {
		logger.Err("Underrun %d of %d writing command to daemon socket\n", tot, len(command))
		daemonSocketRecycle()
		return ""
	}

	// write the packet data to the daemon socket
	daemonSocket.SetWriteDeadline(time.Now().Add(2 * time.Second))
	tot, err = daemonSocket.Write(buffer)

	// on write error recycle the socket connection and return empty result
	if err != nil {
		logger.Err("Error writing data to daemon socket: %v\n", err)
		daemonSocketRecycle()
		return ""
	}

	// on short write recycle the socket connection and return empty result
	if tot != len(buffer) {
		logger.Err("Underrun %d of %d writing data to daemon socket\n", tot, len(buffer))
		daemonSocketRecycle()
		return ""
	}

	// read the reply from the daemon
	daemonSocket.SetReadDeadline(time.Now().Add(2 * time.Second))
	tot, err = daemonSocket.Read(daemonBuffer)

	// on read error recycle the socket connection and return empty result
	if err != nil {
		logger.Err("Error reading reply from daemon socket: %v\n", err)
		daemonSocketRecycle()
		return ""
	}

	// convert the buffer to a string and return the classification result
	reply = string(daemonBuffer)
	logger.Trace("DAEMON REPLY: %s\n", reply)
	return reply
}
