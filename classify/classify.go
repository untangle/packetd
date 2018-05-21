package classify

/*
#include "classify.h"
#cgo LDFLAGS: -ldl -lm -lnavl
*/
import "C"

import (
	"github.com/untangle/packetd/conndict"
	"github.com/untangle/packetd/support"
	"sync"
	"unsafe"
)

var logsrc = "classify"

//-----------------------------------------------------------------------------

// PluginStartup is called to allow plugin specific initialization. We
// increment the argumented WaitGroup so the main process can wait for
// our goodbye function to return during shutdown.
func PluginStartup(childsync *sync.WaitGroup) {
	support.LogMessage(support.LogInfo, logsrc, "PluginStartup(%s) has been called\n", "classify")
	childsync.Add(1)
	C.vendor_startup()
}

//-----------------------------------------------------------------------------

// PluginGoodbye is called when the daemon is shutting down. We call Done
// for the argumented WaitGroup to let the main process know we're finished.
func PluginGoodbye(childsync *sync.WaitGroup) {
	support.LogMessage(support.LogInfo, logsrc, "PluginGoodbye(%s) has been called\n", "classify")
	C.vendor_shutdown()
	childsync.Done()
}

//-----------------------------------------------------------------------------

// PluginNetfilterHandler is called for raw netfilter packets. We pass the
// packet directly to the Sandvine NAVL library for classification, and
// push the results to the conntrack dictionary.
func PluginNetfilterHandler(ch chan<- int32, mess support.TrafficMessage, ctid uint) {
	ptr := (*C.uchar)(unsafe.Pointer(&mess.MsgPacket.Data()[0]))
	C.vendor_classify(ptr, C.int(mess.MsgLength), C.uint(ctid))

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
		support.LogMessage(support.LogWarning, logsrc, "SetPair(navl_appname) ERROR: %s\n", erra)
	} else {
		support.LogMessage(support.LogDebug, logsrc, "SetPair(navl_appname) %d = %s\n", id, app)
	}

	errc := conndict.SetPair("ProtoChain", chain, id)
	if errc != nil {
		support.LogMessage(support.LogWarning, logsrc, "SetPair(navl_protochain) ERROR: %s\n", errc)
	} else {
		support.LogMessage(support.LogDebug, logsrc, "SetPair(navl_protochain) %d = %s\n", id, chain)
	}

}

//-----------------------------------------------------------------------------

//export plugin_attr_callback
func plugin_attr_callback(detail *C.char, ctid C.uint) {
	info := C.GoString(detail)
	id := uint(ctid)

	errd := conndict.SetPair("Detail", info, id)
	if errd != nil {
		support.LogMessage(support.LogWarning, logsrc, "SetPair(attr_detail) ERROR: %s\n", errd)
	} else {
		support.LogMessage(support.LogDebug, logsrc, "SetPair(attr_detail) %d = %s\n", id, info)
	}
}

//-----------------------------------------------------------------------------
