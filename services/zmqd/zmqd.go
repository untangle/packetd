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
	PACKETD_SERVICE = zreq.ZMQRequest_PACKETD
	GET_SESSIONS = zreq.ZMQRequest_GET_SESSIONS
	TEST_INFO = zreq.ZMQRequest_TEST_INFO
)

func Startup() {
	processer := packetdProc(0)
	rzs.Startup(processer)
}

func Shutdown() {
	rzs.Shutdown()
}

func (p packetdProc) Process(request *zreq.ZMQRequest) (processedReply []byte, processErr error) {
	service := request.Service 
	if service != PACKETD_SERVICE {
		return nil, errors.New("Attempting to process a non-packetd request: " + service.String())
	}
	function := request.Function
	reply := &prep.PacketdReply{}

	switch function {
	case GET_SESSIONS:
		conntrackTable, err := dispatch.GetSessions()
		if err != nil {
			return nil, errors.New("Error getting conntrack table " + err.Error())
		}
		var conntrackError error
		reply.Conntracks, conntrackError = dataToProtobufStruct(conntrackTable)
		if conntrackError != nil {
			return nil, errors.New("Error translating conntrack table to protobuf " + conntrackError.Error())
		}
	case TEST_INFO:
		info := retrieveTestInfo()
		var testInfoErr error
		reply.TestInfo, testInfoErr = dataToProtobufStruct(info)
		if testInfoErr != nil {
			return nil, errors.New("Error translating test info to protobuf: " + testInfoErr.Error())
		}
	default:
		reply.ServerError = "Unknown function request to packetd"
	}

	encodedReply, err := proto.Marshal(reply)
	if err != nil {
		return nil, errors.New("Error encoding reply: " + err.Error())
	}

	return encodedReply, nil
}

func (p packetdProc) ProcessError(serverErr string) (processedReply []byte, processErr error) {
	errReply := &prep.PacketdReply{ServerError: serverErr}
	reply, replyErr := proto.Marshal(errReply)
	if replyErr != nil {
		logger.Err("Error on creating error message ", replyErr.Error())
		return nil, replyErr
	}
	return reply, nil
}

func dataToProtobufStruct(info []map[string]interface{}) ([]*spb.Struct, error) {
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