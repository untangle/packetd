package overseer

import (
	"bytes"
	"fmt"
	"sync"
)

var counterTable map[string]uint64
var counterMutex sync.Mutex

// Startup is called to handle service startup
func Startup() {
	counterTable = make(map[string]uint64)
}

// Shutdown is called to handle service shutdown
func Shutdown() {
}

// AddCounter is called to increment a named counter
func AddCounter(name string, amount uint64) uint64 {
	counterMutex.Lock()
	defer counterMutex.Unlock()

	value, found := counterTable[name]
	if found {
		counterTable[name] = value + amount
	} else {
		counterTable[name] = amount
	}

	return counterTable[name]
}

// GetCounter is called to get the value of a named counter
func GetCounter(name string) uint64 {
	counterMutex.Lock()
	defer counterMutex.Unlock()

	value, found := counterTable[name]
	if found {
		return value
	}
	return 0
}

// GenerateReport is called to create a dynamic HTTP page that shows all named counters
func GenerateReport() bytes.Buffer {
	var buffer bytes.Buffer

	counterMutex.Lock()
	defer counterMutex.Unlock()

	buffer.WriteString("<TABLE BORDER=2 CELLPADDING=4 BGCOLOR=#EEEEEE>\r\n")
	buffer.WriteString("<TR><TD><B>Counter Name</B></TD><TD><B>Value</B></TD></TR>\r\n")

	for name, value := range counterTable {
		buffer.WriteString("<TR><TD><TT>")
		buffer.WriteString(name)
		buffer.WriteString("</TT></TD><TD><TT>")
		buffer.WriteString(fmt.Sprintf("%v", value))
		buffer.WriteString("</TT></TD></TR>\n\n")
	}

	buffer.WriteString("</TABLE>\r\n")

	return buffer
}
