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

var isShutdown = make(chan struct{})
var wg sync.WaitGroup

// Processer is function for processing server functions
type Processer interface {
	Process(request *zreq.ZMQRequest) (processedReply []byte, processErr error) 
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
	zmqSocket, err := zmq.NewSocket(zmq.REP)
	if err != nil {
		logger.Warn("Failed to create zmq socket...", err)
	}

	zmqSocket.Bind("tcp://*:5555")
	wg.Add(1)
	go func(waitgroup *sync.WaitGroup, socket *zmq.Socket, proc Processer) {
		defer socket.Close()
		defer waitgroup.Done()
		tick := time.Tick(500 * time.Millisecond)
		for {
			select {
			case <-isShutdown:
				logger.Info("Shutdown is seen\n")
				return
			case <-tick:
				logger.Debug("Listening for requests\n")
				requestRaw, err := socket.RecvMessageBytes(zmq.DONTWAIT)
				if err != nil {
					if zmq.AsErrno(err) != zmq.AsErrno(syscall.EAGAIN) {
						logger.Warn("Error on receive ", err, "\n")
					}
					continue
				}

				// Process message
				request := &zreq.ZMQRequest{}
				if err := proto.Unmarshal(requestRaw[0], request); err != nil {
					logger.Warn("Error on unmasharlling ", err, "\n")
					continue
				}
				logger.Info("Received ", request, "\n")

				reply, err := processMessage(proc, request)
				if err != nil {
					logger.Warn("Error on processing reply: ", err, "\n")
					continue
				}

				socket.SendMessage(reply)
				logger.Info("Sent ", reply, "\n")
			}
		} 
	}(&wg, zmqSocket, processer)
}

/* helper function that calls the interface's process function */
func processMessage(proc Processer, request *zreq.ZMQRequest) (processedReply []byte, processErr error) {
	return proc.Process(request)
}