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

var appname = "classify"

//-----------------------------------------------------------------------------

// PluginStartup is called to allow plugin specific initialization. We
// increment the argumented WaitGroup so the main process can wait for
// our goodbye function to return during shutdown.
func PluginStartup(childsync *sync.WaitGroup) {
	support.LogMessage(support.LogInfo, appname, "PluginStartup(%s) has been called\n", "classify")
	C.vendor_startup()
	support.InsertNetfilterSubscription(appname, 1, PluginNetfilterHandler)
	childsync.Add(1)
}

//-----------------------------------------------------------------------------

// PluginGoodbye is called when the daemon is shutting down. We call Done
// for the argumented WaitGroup to let the main process know we're finished.
func PluginGoodbye(childsync *sync.WaitGroup) {
	support.LogMessage(support.LogInfo, appname, "PluginGoodbye(%s) has been called\n", "classify")
	C.vendor_shutdown()
	childsync.Done()
}

//-----------------------------------------------------------------------------

// PluginNetfilterHandler is called for raw netfilter packets. We pass the
// packet directly to the Sandvine NAVL library for classification, and
// push the results to the conntrack dictionary.
func PluginNetfilterHandler(ch chan<- support.SubscriptionResult, mess support.TrafficMessage, ctid uint) {
	ptr := (*C.uchar)(unsafe.Pointer(&mess.MsgPacket.Data()[0]))
	C.vendor_classify(ptr, C.int(mess.MsgLength), C.uint(ctid))

	var result support.SubscriptionResult
	result.Owner = appname
	result.PacketMark = 0
	result.SessionRelease = false

	// use the channel to return our result
	ch <- result
}

//-----------------------------------------------------------------------------

//export plugin_navl_callback
func plugin_navl_callback(application *C.char, protochain *C.char, ctid C.uint) {

	app := C.GoString(application)
	chain := C.GoString(protochain)
	id := uint(ctid)

	erra := conndict.SetPair("Application", app, id)
	if erra != nil {
		support.LogMessage(support.LogWarning, appname, "SetPair(Application) ERROR: %s\n", erra)
	} else {
		support.LogMessage(support.LogDebug, appname, "SetPair(Application) %d = %s\n", id, app)
	}

	errc := conndict.SetPair("ProtoChain", chain, id)
	if errc != nil {
		support.LogMessage(support.LogWarning, appname, "SetPair(ProtoChain) ERROR: %s\n", errc)
	} else {
		support.LogMessage(support.LogDebug, appname, "SetPair(ProtoChain) %d = %s\n", id, chain)
	}

}

//-----------------------------------------------------------------------------

//export plugin_attr_callback
func plugin_attr_callback(detail *C.char, ctid C.uint) {
	info := C.GoString(detail)
	id := uint(ctid)

	errd := conndict.SetPair("Detail", info, id)
	if errd != nil {
		support.LogMessage(support.LogWarning, appname, "SetPair(attr_detail) ERROR: %s\n", errd)
	} else {
		support.LogMessage(support.LogDebug, appname, "SetPair(attr_detail) %d = %s\n", id, info)
	}
}

//-----------------------------------------------------------------------------
