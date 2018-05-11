package classify

/*
#include "string.h"
#include "stdlib.h"
#include "stdarg.h"
#include "syslog.h"
#include "stdio.h"
#include "ctype.h"
#include "math.h"
#include "time.h"
#include "sys/time.h"
#include "pthread.h"
#include "navl.h"
#include "classify.h"
#cgo LDFLAGS: -lnavl -lm -ldl
*/
import "C"

import (
	"github.com/untangle/packetd/support"
	"sync"
	"unsafe"
)

//-----------------------------------------------------------------------------

// PluginStartup is called to allow plugin specific initialization. We
// increment the argumented WaitGroup so the main process can wait for
// our goodbye function to return during shutdown.
func PluginStartup(childsync *sync.WaitGroup) {
	support.LogMessage("PluginStartup(%s) has been called\n", "classify")
	childsync.Add(1)
	C.vendor_startup()
}

//-----------------------------------------------------------------------------

// PluginGoodbye is called when the daemon is shutting down. We call Done
// for the argumented WaitGroup to let the main process know we're finished.
func PluginGoodbye(childsync *sync.WaitGroup) {
	support.LogMessage("PluginGoodbye(%s) has been called\n", "classify")
	C.vendor_shutdown()
	childsync.Done()
}

//-----------------------------------------------------------------------------

// PluginNetfilterHandler is called for raw netfilter packets. We pass the
// packet directly to the Sandvine NAVL library for classification, and
// push the results to the conntrack dictionary.
// TODO - need indirect way to call the NAVL library for GPL compliance
func PluginNetfilterHandler(ch chan<- int32, buffer []byte, length int, ctid uint) {
	ptr := (*C.uchar)(unsafe.Pointer(&buffer[0]))
	C.vendor_classify(ptr, C.int(length))

	// TODO - put the classification in the session object

	// use the channel to return our mark bits
	ch <- 2
}

//-----------------------------------------------------------------------------
