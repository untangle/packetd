package zmqd

import (
	"errors"

	rzs "github.com/untangle/golang-shared/services/restdZmqServer"
	prep "github.com/untangle/golang-shared/structs/protocolbuffers/PacketdReply"
	zreq "github.com/untangle/golang-shared/structs/protocolbuffers/ZMQRequest"
	"github.com/untangle/packetd/services/dispatch"
	"google.golang.org/protobuf/proto"
	spb "google.golang.org/protobuf/types/known/structpb"
)

type packetdProc int 

const (
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
	}

	encodedReply, err := proto.Marshal(reply)
	if err != nil {
		return nil, errors.New("Error encoding reply: " + err.Error())
	}

	return encodedReply, nil
}

func dataToProtobufStruct(info []map[string]interface{}) ([]*spb.Struct, error) {
	var protobufStruct []*spb.Struct
	for _, v := range info {
		infoStruct, err := spb.NewStruct(v)

		if err != nil {
			return nil, errors.New("Error getting conntrack table: " + err.Error())
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