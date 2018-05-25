package geoip

import (
	"compress/gzip"
	"github.com/oschwald/geoip2-golang"
	"github.com/untangle/packetd/conndict"
	"github.com/untangle/packetd/support"
	"io"
	"net/http"
	"os"
	"sync"
)

var appname = "geoip"
var geodb *geoip2.Reader

//-----------------------------------------------------------------------------

// PluginStartup is called to allow plugin specific initialization.
// We initialize an instance of the GeoIP engine using any existing
// database we can find, or we download if needed. We increment the
// argumented WaitGroup so the main process can wait for our goodbye function
// to return during shutdown.
func PluginStartup(childsync *sync.WaitGroup) {
	support.LogMessage(support.LogInfo, appname, "PluginStartup(%s) has been called\n", "geoip")

	var filename string

	// start by looking for the NGFW city database file
	filename = "/var/cache/untangle-geoip/GeoLite2-City.mmdb"
	_, err := os.Stat(filename)

	// if not found look for the MicroFW country database file
	if os.IsNotExist(err) {
		filename = "/tmp/GeoLite2-Country.mmdb" // TODO - where should this file be stored?
		_, err := os.Stat(filename)

		// if still not found download the country database
		if os.IsNotExist(err) {
			databaseDownload(filename)
		}
	}

	db, err := geoip2.Open(filename)
	if err != nil {
		support.LogMessage(support.LogWarning, appname, "Unable to load GeoIP Database: %s\n", err)
	} else {
		support.LogMessage(support.LogInfo, appname, "Loading GeoIP Database: %s\n", filename)
		geodb = db
	}

	support.InsertNetfilterSubscription(appname, 1, PluginNetfilterHandler)
	childsync.Add(1)
}

//-----------------------------------------------------------------------------

// PluginGoodbye is called when the daemon is shutting down. We close our
// GeoIP engine and call done for the argumented WaitGroup to let the main
// process know we're finished.
func PluginGoodbye(childsync *sync.WaitGroup) {
	support.LogMessage(support.LogInfo, appname, "PluginGoodbye(%s) has been called\n", "geoip")
	geodb.Close()
	childsync.Done()
}

//-----------------------------------------------------------------------------

// PluginNetfilterHandler is called to handle netfilter packet data. We extract
// the source and destination IP address from the packet, lookup the GeoIP
// country code for each, and store them in the conntrack dictionary.
func PluginNetfilterHandler(ch chan<- support.SubscriptionResult, mess support.TrafficMessage, ctid uint) {
	var SrcCode = "XX"
	var DstCode = "XX"

	SrcRecord, err := geodb.City(mess.MsgIP.SrcIP)
	if (err == nil) && (len(SrcRecord.Country.IsoCode) != 0) {
		SrcCode = SrcRecord.Country.IsoCode
		support.LogMessage(support.LogDebug, appname, "SRC: %s = %s\n", mess.MsgIP.SrcIP, SrcCode)
	}

	DstRecord, err := geodb.City(mess.MsgIP.DstIP)
	if (err == nil) && (len(DstRecord.Country.IsoCode) != 0) {
		DstCode = DstRecord.Country.IsoCode
		support.LogMessage(support.LogDebug, appname, "DST: %s = %s\n", mess.MsgIP.DstIP, DstCode)
	}

	errc := conndict.SetPair("SrcCountry", SrcCode, ctid)
	if errc != nil {
		support.LogMessage(support.LogWarning, appname, "SetPair(client) ERROR: %s\n", errc)
	} else {
		support.LogMessage(support.LogDebug, appname, "SetPair(client) %d = %s\n", ctid, SrcCode)
	}

	errs := conndict.SetPair("DstCountry", DstCode, ctid)
	if errs != nil {
		support.LogMessage(support.LogWarning, appname, "SetPair(server) ERROR: %s\n", errs)
	} else {
		support.LogMessage(support.LogDebug, appname, "SetPair(server) %d = %s\n", ctid, DstCode)
	}

	var result support.SubscriptionResult
	result.Owner = appname
	result.PacketMark = 0
	result.SessionRelease = true
	ch <- result
}

//-----------------------------------------------------------------------------

func databaseDownload(filename string) {
	support.LogMessage(support.LogInfo, appname, "Downloading GeoIP Database\n")

	// Get the GeoIP database from MaxMind
	resp, err := http.Get("http://geolite.maxmind.com/download/geoip/database/GeoLite2-Country.mmdb.gz")
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Check server response
	if resp.StatusCode != http.StatusOK {
		support.LogMessage(support.LogWarning, appname, "Download failure: %s\n", resp.Status)
		return
	}

	// Create a reader for the compressed data
	reader, err := gzip.NewReader(resp.Body)
	if err != nil {
		return
	}
	defer reader.Close()

	// Create the output file
	writer, err := os.Create(filename)
	if err != nil {
		return
	}
	defer writer.Close()

	// Write the uncompressed database to the file
	io.Copy(writer, reader)
}

//-----------------------------------------------------------------------------
