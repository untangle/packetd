package classify

// TODO - need indirect way to call the NAVL library for GPL compliance

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
	"github.com/untangle/packetd/conndict"
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
func PluginNetfilterHandler(ch chan<- int32, buffer []byte, length int, ctid uint) {
	ptr := (*C.uchar)(unsafe.Pointer(&buffer[0]))
	C.vendor_classify(ptr, C.int(length), C.uint(ctid))

	// use the channel to return our mark bits
	ch <- 2
}

//-----------------------------------------------------------------------------

//export plugin_navl_callback
func plugin_navl_callback(appname *C.char, protochain *C.char, ctid C.uint) {
	app := C.GoString(appname)
	chain := C.GoString(protochain)
	id := uint(ctid)

	erra := conndict.SetPair("AppName", app, id)
	if erra != nil {
		support.LogMessage("SetPair(navl_appname) ERROR: %s\n", erra)
	} else {
		support.LogMessage("SetPair(navl_appname) %d = %s\n", id, app)
	}

	errc := conndict.SetPair("ProtoChain", chain, id)
	if errc != nil {
		support.LogMessage("SetPair(navl_protochain) ERROR: %s\n", errc)
	} else {
		support.LogMessage("SetPair(navl_protochain) %d = %s\n", id, chain)
	}

}

//-----------------------------------------------------------------------------

//export plugin_attr_callback
func plugin_attr_callback(detail *C.char, ctid C.uint) {
	info := C.GoString(detail)
	id := uint(ctid)

	errd := conndict.SetPair("Detail", info, id)
	if errd != nil {
		support.LogMessage("SetPair(attr_detail) ERROR: %s\n", errd)
	} else {
		support.LogMessage("SetPair(attr_detail) %d = %s\n", id, info)
	}
}

//-----------------------------------------------------------------------------
