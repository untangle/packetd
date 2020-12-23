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

	if function == "GetConntrackTable" {
		conntrackTable, err := dispatch.GetSessions()
		if err != nil {
			return nil, errors.New("Error getting conntrack table " + err.Error())
		}
		for _, v := range conntrackTable {
			conntrackStruct, err := spb.NewStruct(v)

			if err != nil {
				return nil, errors.New("Error getting conntrack table: " + err.Error())
			}

			reply.Conntracks = append(reply.Conntracks, conntrackStruct)
		}
		
		
	}

	encodedReply, err := proto.Marshal(reply)
	if err != nil {
		return nil, errors.New("Error encoding reply: " + err.Error())
	}

	return encodedReply, nil
}