package dispatch

import (
	"bytes"
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

	// return strconv.Itoa(int(t.Protocol)) + "|" + t.ClientAddress.String() + ":" + strconv.Itoa(int(t.ClientPort)) + "->" + t.ServerAddress.String() + ":" + strconv.Itoa(int(t.ServerPort))

	var buffer bytes.Buffer
	buffer.WriteString(strconv.Itoa(int(t.Protocol)))
	buffer.WriteString("|")
	buffer.WriteString(t.ClientAddress.String())
	buffer.WriteString(":")
	buffer.WriteString(strconv.Itoa(int(t.ClientPort)))
	buffer.WriteString("->")
	buffer.WriteString(t.ServerAddress.String())
	buffer.WriteString(":")
	buffer.WriteString(strconv.Itoa(int(t.ServerPort)))
	return buffer.String()
}

// StringReverse returns string representation of reverse tuple
func (t Tuple) StringReverse() string {

	// return strconv.Itoa(int(t.Protocol)) + "|" + t.ServerAddress.String() + ":" + strconv.Itoa(int(t.ServerPort)) + "->" + t.ClientAddress.String() + ":" + strconv.Itoa(int(t.ClientPort))

	var buffer bytes.Buffer
	buffer.WriteString(strconv.Itoa(int(t.Protocol)))
	buffer.WriteString("|")
	buffer.WriteString(t.ServerAddress.String())
	buffer.WriteString(":")
	buffer.WriteString(strconv.Itoa(int(t.ServerPort)))
	buffer.WriteString("->")
	buffer.WriteString(t.ClientAddress.String())
	buffer.WriteString(":")
	buffer.WriteString(strconv.Itoa(int(t.ClientPort)))
	return buffer.String()
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

// EqualReverse returns true if two Tuples are equal when one is inversed in the other direction, false otherwise
// 1.2.3.4:5 -> 6.7.8.9:0 == 6.7.8.9:0 -> 1.2.3.4:5 = true
func (t Tuple) EqualReverse(o Tuple) bool {
	if t.Protocol != o.Protocol ||
		!t.ClientAddress.Equal(o.ServerAddress) ||
		!t.ServerAddress.Equal(o.ClientAddress) ||
		t.ClientPort != o.ServerPort ||
		t.ServerPort != o.ClientPort {
		return false
	}
	return true
}
