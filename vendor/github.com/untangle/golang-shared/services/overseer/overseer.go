package overseer

import (
	"bytes"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
)

/*
	Class for managing named counters. The map is allocated as an array
	of value pointers that are created the first time a named counter
	is updated. The map is protected by a RWMutex that we only need to
	lock for writing when new counters are created. Otherwise we
	read lock to get the pointer and manage the values atomically.
*/

var counterTable map[string]*int64
var counterMutex sync.RWMutex

// Startup is called to handle service startup
func Startup() {
	counterTable = make(map[string]*int64)
}

// Shutdown is called to handle service shutdown
func Shutdown() {
}

// AddCounter is called to add the argumented value to a named counter
func AddCounter(name string, amount int64) int64 {
	counterMutex.RLock()
	ptr, found := counterTable[name]
	counterMutex.RUnlock()

	// if we found the counter add the amount and return the new value
	if found {
		return atomic.AddInt64(ptr, amount)
	}

	// not found so create and safely put in table
	val := new(int64)
	atomic.StoreInt64(val, amount)
	counterMutex.Lock()
	counterTable[name] = val
	counterMutex.Unlock()

	return amount
}

// IncCounter is called to increment a named counter
func IncCounter(name string) int64 {
	counterMutex.RLock()
	ptr, found := counterTable[name]
	counterMutex.RUnlock()

	// if we found the counter add one and return the new value
	if found {
		return atomic.AddInt64(ptr, 1)
	}

	// not found so create and safely store in table with initial value
	val := new(int64)
	atomic.StoreInt64(val, 1)
	counterMutex.Lock()
	counterTable[name] = val
	counterMutex.Unlock()

	return 1
}

// DecCounter is called to decrement a named counter
func DecCounter(name string) int64 {
	counterMutex.RLock()
	ptr, found := counterTable[name]
	counterMutex.RUnlock()

	// if we found the counter subtract one and return the new value
	if found {
		return atomic.AddInt64(ptr, -1)
	}

	// not found so create and safely store in table with initial value
	val := new(int64)
	atomic.StoreInt64(val, -1)
	counterMutex.Lock()
	counterTable[name] = val
	counterMutex.Unlock()

	return -1
}

// GetCounter is called to get the value of a named counter
func GetCounter(name string) int64 {
	counterMutex.RLock()
	ptr, found := counterTable[name]
	counterMutex.RUnlock()

	if found {
		return atomic.LoadInt64(ptr)
	}

	return 0
}

// GenerateReport is called to create a dynamic HTTP page that shows all named counters
func GenerateReport(buffer *bytes.Buffer) {
	counterMutex.RLock()
	defer counterMutex.RUnlock()

	// create a sorted list of the counter names
	namelist := make([]string, 0, len(counterTable))
	for name := range counterTable {
		namelist = append(namelist, name)
	}
	sort.Strings(namelist)

	buffer.WriteString("<TABLE BORDER=2 CELLPADDING=4 BGCOLOR=#EEEEEE>\r\n")
	buffer.WriteString("<TR><TH COLSPAN=2>Overseer Debug Counters</TH></TR>\r\n")
	buffer.WriteString("<TR><TD><B>Counter Name</B></TD><TD><B>Value</B></TD></TR>\r\n")

	for _, name := range namelist {
		ptr := counterTable[name]
		value := atomic.LoadInt64(ptr)
		buffer.WriteString("<TR><TD><TT>")
		buffer.WriteString(name)
		buffer.WriteString("</TT></TD><TD><TT>")
		buffer.WriteString(fmt.Sprintf("%v", value))
		buffer.WriteString("</TT></TD></TR>\n\n")
	}

	buffer.WriteString("</TABLE>\r\n")
}
