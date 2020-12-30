package zmqd

import (
	"errors"

	"github.com/untangle/golang-shared/services/logger"
	rzs "github.com/untangle/golang-shared/services/restdZmqServer"
	prep "github.com/untangle/golang-shared/structs/protocolbuffers/PacketdReply"
	zreq "github.com/untangle/golang-shared/structs/protocolbuffers/ZMQRequest"
	"github.com/untangle/packetd/services/dispatch"
	"google.golang.org/protobuf/proto"
	spb "google.golang.org/protobuf/types/known/structpb"
)

type packetdProc int 

const (
	// PacketdService is the ZMQRequest packetd service
	PacketdService = zreq.ZMQRequest_PACKETD
	// GetSessions is the ZMQRequest GET_SESSIONS function
	GetSessions = zreq.ZMQRequest_GET_SESSIONS
	// TestInfo is the ZMQRequest TEST_INFO function
	TestInfo = zreq.ZMQRequest_TEST_INFO
)

// Startup starts the zmq socket via restdZmqServer
func Startup() {
	processer := packetdProc(0)
	rzs.Startup(processer)
}

// Shutdown shuts down the zmq socket via restdZmqServer
func Shutdown() {
	rzs.Shutdown()
}

// Process is the packetdProc interface Process function implementation for restdZmqServer
// It processes the ZMQRequest and retrives the correct information from packetd
func (p packetdProc) Process(request *zreq.ZMQRequest) (processedReply []byte, processErr error) {
	// Check the request is for packetd
	service := request.Service 
	if service != PacketdService {
		return nil, errors.New("Attempting to process a non-packetd request: " + service.String())
	}

	// Get the function and prepare the reply
	function := request.Function
	reply := &prep.PacketdReply{}

	// Based on the Function, retrive the proper information
	switch function {
	case GetSessions:
		// GetSessions gets the conntrack/dict sessions tuple map
		conntrackTable, err := dispatch.GetSessions()
		if err != nil {
			return nil, errors.New("Error getting conntrack table " + err.Error())
		}

		// Convert table to protobuf
		var conntrackError error
		reply.Conntracks, conntrackError = dataToProtobufStruct(conntrackTable)
		if conntrackError != nil {
			return nil, errors.New("Error translating conntrack table to protobuf " + conntrackError.Error())
		}
	case TestInfo:
		// TestInfo gets the test info for packetd for zmq testing
		info := retrieveTestInfo()

		// Convert table to protobuf
		var testInfoErr error
		reply.TestInfo, testInfoErr = dataToProtobufStruct(info)
		if testInfoErr != nil {
			return nil, errors.New("Error translating test info to protobuf: " + testInfoErr.Error())
		}
	default:
		// An unknown function sets the reply error
		reply.ServerError = "Unknown function request to packetd"
	}

	// Encode the reply
	encodedReply, err := proto.Marshal(reply)
	if err != nil {
		return nil, errors.New("Error encoding reply: " + err.Error())
	}

	return encodedReply, nil
}

// ProcessError is the packetd implementation of the ProcessError function for restdZmqServer
func (p packetdProc) ProcessError(serverErr string) (processedReply []byte, processErr error) {
	// Set the ServerError in the PacketdReply
	errReply := &prep.PacketdReply{ServerError: serverErr}

	// Encode the reply
	reply, replyErr := proto.Marshal(errReply)
	if replyErr != nil {
		logger.Err("Error on creating error message ", replyErr.Error())
		return nil, replyErr
	}
	return reply, nil
}

// dataToProtobufStruct converts the returned packetd data into a protobuf
func dataToProtobufStruct(info []map[string]interface{}) ([]*spb.Struct, error) {
	// loop through the information and convert to a protobuf struct
	var protobufStruct []*spb.Struct
	for _, v := range info {
		infoStruct, err := spb.NewStruct(v)

		if err != nil {
			return nil, errors.New("Error translating data to a protobuf: " + err.Error())
		}

		protobufStruct = append(protobufStruct, infoStruct)
	}

	return protobufStruct, nil
}

// retrieveTestInfo creates test info to test zmq 
func retrieveTestInfo() []map[string]interface{} {
	var tests []map[string]interface{}
	m1 := make(map[string]interface{})
	m1["ping"] = "pong"
	m1["tennis"] = "ball"
	tests = append(tests, m1)
	tests = append(tests, m1)
	m2 := make(map[string]interface{})
	m2["pong"] = "ping"
	m2["ball"] = "tennis"
	tests = append(tests, m2)
	tests = append(tests, m2)

	return tests
}