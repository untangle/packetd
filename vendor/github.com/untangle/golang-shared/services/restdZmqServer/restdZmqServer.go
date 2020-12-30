package restdzmqserver

import (
	"sync"
	"syscall"
	"time"

	zmq "github.com/pebbe/zmq4"
	"github.com/untangle/golang-shared/services/logger"
	zreq "github.com/untangle/golang-shared/structs/protocolbuffers/ZMQRequest"
	"google.golang.org/protobuf/proto"
)

const (
	// ServerTick is tick for when server receives bytes
	ServerTick = 500 * time.Millisecond
)

// Variables for initiating a graceful shutdown
var isShutdown = make(chan struct{})
var wg sync.WaitGroup

// Processer is an interface for server processing functions 
type Processer interface {
	Process(request *zreq.ZMQRequest) ([]byte, error) 
	ProcessError(processError string) ([]byte, error)
}

// Startup the server function 
func Startup(processer Processer) {
	logger.Info("Starting zmq service...\n")
	socketServer(processer)
}

// Shutdown the server function 
func Shutdown() {
	close(isShutdown)
	wg.Wait()
}

/* Main server funcion, creates socket and runs goroutine to keep server open */
func socketServer(processer Processer) {
	// Set up socket 
	zmqSocket, err := zmq.NewSocket(zmq.REP)
	if err != nil {
		logger.Warn("Failed to create zmq socket...", err)
	}

	// Put socket into the waitgroup
	zmqSocket.Bind("tcp://*:5555")
	wg.Add(1)

	// Go routine for running the server
	go func(waitgroup *sync.WaitGroup, socket *zmq.Socket, proc Processer) {
		// Close socket and signal waitgroup is done
		defer socket.Close()
		defer waitgroup.Done()
		tick := time.Tick(ServerTick)

		// Infinite for loop that quits when shutdown channel is closed
		// Receives message bytes on the tick
		for {
			select {
			case <-isShutdown:
				logger.Info("Shutdown is seen\n")
				return
			case <-tick:
				logger.Debug("Listening for requests\n")
				serverErr := ""
				var reply []byte
				var replyErr error

				// Receive message bytes, don't have it block
				requestRaw, err := socket.RecvMessageBytes(zmq.DONTWAIT)
				if err != nil {
					// When nothing is received, EAGAIN is thrown, but we do nothing to handle this
					if zmq.AsErrno(err) == zmq.AsErrno(syscall.EAGAIN) {
						continue
					}
					// Any other errors on receive is an error that requires the socket to send
					serverErr = "Error on receive " + err.Error()
				} else {
					// Unmarshall the request and set error if any is found
					request := &zreq.ZMQRequest{}
					err := proto.Unmarshal(requestRaw[0], request)
					if err != nil {
						serverErr = "Error on unmasharling " + err.Error()
					} else {
						// Process message if unmarshal is successful and set set error if any error found
						logger.Debug("Received ", request, "\n")

						reply, replyErr = processMessage(proc, request)
						if replyErr != nil {
							serverErr = "Error on processing reply: " + replyErr.Error()
						}
					}
				}

				// If a server error is found, package it in a reply
				if len(serverErr) > 0 {
					logger.Info(serverErr, "\n")
					reply, replyErr = processErrorMessage(proc, serverErr)
					// If processing the error fails, send an empty byte array so the client knows
					if replyErr != nil {
						reply = make([]byte, 0)
					}
				}

				// Send message
				socket.SendMessage(reply)
				logger.Debug("Sent ", reply, "\n")
			}
		} 
	}(&wg, zmqSocket, processer)
}

/* helper function that calls the interface's process function */
func processMessage(proc Processer, request *zreq.ZMQRequest) (processedReply []byte, processErr error) {
	return proc.Process(request)
}

/* helper function that calls the interface's processError function */
func processErrorMessage(proc Processer, serverErr string) (processedReply []byte, processErr error) {
	return proc.ProcessError(serverErr)
}