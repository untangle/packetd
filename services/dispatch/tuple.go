package dispatch

import (
	"net"
	"strconv"
)

// Tuple represent a session using the protocol and source and destination address and port values.
type Tuple struct {
	Protocol      uint8
	ClientAddress net.IP
	ClientPort    uint16
	ServerAddress net.IP
	ServerPort    uint16
}

// String returns string representation of tuple
func (t Tuple) String() string {
	return strconv.Itoa(int(t.Protocol)) + "|" + t.ClientAddress.String() + ":" + strconv.Itoa(int(t.ClientPort)) + "->" + t.ServerAddress.String() + ":" + strconv.Itoa(int(t.ServerPort))
}

// Equal returns true if two Tuples are equal, false otherwise
func (t Tuple) Equal(o Tuple) bool {
	if t.Protocol != o.Protocol ||
		!t.ClientAddress.Equal(o.ClientAddress) ||
		!t.ServerAddress.Equal(o.ServerAddress) ||
		t.ClientPort != o.ClientPort ||
		t.ServerPort != o.ServerPort {
		return false
	}
	return true
}
