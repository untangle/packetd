package predicttrafficsvc

/*
	These are structures and functions for representing and encoding DNS queries.
	Using the DNS stuff in gopacket/layers was problematic because they do a lot
	of sanity checking on the q.Type and q.Class since they expect it to be used
	for actual DNS. We're just making use of an existing protocol to simplify our
	prediction service, and need to be able to use generic int values in the query
	fields. I crafted what follows using the code from this project:
	https://github.com/vishen/go-dnsquery
*/

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

type DNSQuery struct {
	ID     uint16
	QR     int
	OpCode uint8

	AA int
	TC int
	RD int
	RA int
	Z  uint8

	ResponseCode uint8

	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16

	Questions []DNSQuestion
}

func (q DNSQuery) encode() []byte {
	var buffer bytes.Buffer
	var lohead uint8
	var hihead uint8

	binary.Write(&buffer, binary.BigEndian, q.ID)

	q.QDCount = uint16(len(q.Questions))

	lohead = (uint8(q.QR)<<7 | uint8(q.OpCode)<<3 | uint8(q.AA)<<1 | uint8(q.RD))
	hihead = (uint8(q.RA)<<7 | uint8(q.Z)<<4)

	binary.Write(&buffer, binary.BigEndian, lohead)
	binary.Write(&buffer, binary.BigEndian, hihead)
	binary.Write(&buffer, binary.BigEndian, q.QDCount)
	binary.Write(&buffer, binary.BigEndian, q.ANCount)
	binary.Write(&buffer, binary.BigEndian, q.NSCount)
	binary.Write(&buffer, binary.BigEndian, q.ARCount)

	for _, question := range q.Questions {
		buffer.Write(question.encode())
	}

	return buffer.Bytes()
}

type DNSQuestion struct {
	Name  string
	Type  uint16
	Class uint16
}

func (q DNSQuestion) encode() []byte {
	var buffer bytes.Buffer

	domainParts := strings.Split(q.Name, ".")
	for _, part := range domainParts {
		if err := binary.Write(&buffer, binary.BigEndian, byte(len(part))); err != nil {
			fmt.Printf("Error binary.Write(..) for '%s': '%s'", part, err)
		}

		for _, c := range part {
			if err := binary.Write(&buffer, binary.BigEndian, uint8(c)); err != nil {
				fmt.Printf("Error binary.Write(..) for '%s'; '%c': '%s'", part, c, err)
			}
		}
	}

	binary.Write(&buffer, binary.BigEndian, uint8(0))
	binary.Write(&buffer, binary.BigEndian, q.Type)
	binary.Write(&buffer, binary.BigEndian, q.Class)

	return buffer.Bytes()
}
