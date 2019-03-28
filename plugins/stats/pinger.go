package stats

/*
	This is a function to ping a target address using a specific local interface and calculate the latency.
	Crafted with bits and pieces pulled from the sources listed below.

	https://github.com/sparrc/go-ping
	https://stackoverflow.com/questions/2937123/implementing-icmp-ping-in-go/27773040
*/

import (
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	protoIGNORE = 0
	protoICMP4  = 1
	protoICMP6  = 58
)

func pingNetworkAddress(protocol int, localAddr string, targetAddr string) (time.Duration, error) {
	var netaddr *net.IPAddr
	var conn *icmp.PacketConn
	var reply *icmp.Message
	var mess icmp.Message
	var buffer []byte
	var protstr string
	var err error
	var ourpid int
	var ourseq int

	if protocol == protoICMP6 {
		netaddr, err = net.ResolveIPAddr("ip6", targetAddr)
	} else {
		netaddr, err = net.ResolveIPAddr("ip4", targetAddr)
	}

	if err != nil {
		return 0, err
	}

	buffer = make([]byte, 1500)
	ourpid = os.Getpid() & 0xFFFF
	ourseq = randGen.Intn(0xFFFF)

	mess.Code = 0
	mess.Body = &icmp.Echo{
		ID:   ourpid,
		Seq:  ourseq,
		Data: []byte("Untangle MicroFirewall Network Latency Probe"),
	}

	if protocol == protoICMP6 {
		protstr = "ip6:ipv6-icmp"
		mess.Type = ipv6.ICMPTypeEchoRequest
	} else {
		protstr = "ip4:icmp"
		mess.Type = ipv4.ICMPTypeEcho
	}

	conn, err = icmp.ListenPacket(protstr, localAddr)
	if err != nil {
		return 0, err
	}

	defer conn.Close()

	data, err := mess.Marshal(nil)

	if err != nil {
		return 0, err
	}

	transmit := time.Now()

	if _, err := conn.WriteTo(data, &net.IPAddr{IP: netaddr.IP}); err != nil {
		return 0, err
	}

	conn.SetReadDeadline(time.Now().Add(time.Millisecond * 1000 * pingCheckTimeoutSec))
	size, peer, err := conn.ReadFrom(buffer)

	duration := time.Since(transmit)

	if err != nil {
		return 0, err
	}

	reply, err = icmp.ParseMessage(protocol, buffer[:size])

	if err != nil {
		return 0, err
	}

	if reply.Type != ipv4.ICMPTypeEchoReply && reply.Type != ipv6.ICMPTypeEchoReply {
		return 0, fmt.Errorf("unexpected ICMP reply type:%d from:%v", reply.Type, peer)

	}

	answer := reply.Body.(*icmp.Echo)

	if answer.ID != ourpid {
		return 0, fmt.Errorf("mismatched ID - received:%d expecting:%d", answer.ID, ourpid)
	}

	if answer.Seq != ourseq {
		return 0, fmt.Errorf("mismatched SEQ - received:%d expecting %d", answer.Seq, ourseq)
	}

	return duration, nil
}
