package geoip

import (
	"compress/gzip"
	"github.com/oschwald/geoip2-golang"
	"github.com/untangle/packetd/services/dict"
	"github.com/untangle/packetd/services/dispatch"
	"github.com/untangle/packetd/services/logger"
	"io"
	"net/http"
	"os"
)

const pluginName = "geoip"

var geodb *geoip2.Reader

// PluginStartup is called to allow plugin specific initialization.
// We initialize an instance of the GeoIP engine using any existing
// database we can find, or we download if needed. We increment the
// argumented WaitGroup so the main process can wait for our shutdown function
// to return during shutdown.
func PluginStartup() {
	logger.Info("PluginStartup(%s) has been called\n", pluginName)

	var filename string

	// start by looking for the NGFW city database file
	filename = "/var/cache/untangle-geoip/GeoLite2-City.mmdb"
	_, err := os.Stat(filename)

	// if not found look for the MicroFW country database file
	if os.IsNotExist(err) {
		filename = "/usr/share/untangle-geoip/GeoLite2-Country.mmdb" // TODO - where should this file be stored?
		_, err := os.Stat(filename)

		// if still not found download the country database
		if os.IsNotExist(err) {
			databaseDownload(filename)
		}
	}

	db, err := geoip2.Open(filename)
	if err != nil {
		logger.Warn("Unable to load GeoIP Database: %s\n", err)
	} else {
		logger.Info("Loading GeoIP Database: %s\n", filename)
		geodb = db
	}

	dispatch.InsertNfqueueSubscription(pluginName, 2, PluginNfqueueHandler)
}

// PluginShutdown is called when the daemon is shutting down. We close our
// GeoIP engine and call done for the argumented WaitGroup to let the main
// process know we're finished.
func PluginShutdown() {
	logger.Info("PluginShutdown(%s) has been called\n", pluginName)
	if geodb != nil {
		geodb.Close()
	}
}

// PluginNfqueueHandler is called to handle nfqueue packet data. We extract
// the source and destination IP address from the packet, lookup the GeoIP
// country code for each, and store them in the conntrack dictionary.
func PluginNfqueueHandler(mess dispatch.NfqueueMessage, ctid uint32, newSession bool) dispatch.NfqueueResult {
	var result dispatch.NfqueueResult
	result.Owner = "geoip"
	result.PacketMark = 0
	result.SessionRelease = true

	if geodb == nil {
		return result
	}

	var SrcCode = "XX"
	var DstCode = "XX"

	SrcRecord, err := geodb.City(mess.IPlayer.SrcIP)
	if (err == nil) && (len(SrcRecord.Country.IsoCode) != 0) {
		SrcCode = SrcRecord.Country.IsoCode
		logger.Debug("SRC: %s = %s\n", mess.IPlayer.SrcIP, SrcCode)
	}

	DstRecord, err := geodb.City(mess.IPlayer.DstIP)
	if (err == nil) && (len(DstRecord.Country.IsoCode) != 0) {
		DstCode = DstRecord.Country.IsoCode
		logger.Debug("DST: %s = %s\n", mess.IPlayer.DstIP, DstCode)
	}

	dict.AddSessionEntry(ctid, "client_country", SrcCode)
	dict.AddSessionEntry(ctid, "server_country", DstCode)

	return result
}

func databaseDownload(filename string) {
	logger.Info("Downloading GeoIP Database\n")

	// Get the GeoIP database from MaxMind
	resp, err := http.Get("http://geolite.maxmind.com/download/geoip/database/GeoLite2-Country.mmdb.gz")
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Check server response
	if resp.StatusCode != http.StatusOK {
		logger.Warn("Download failure: %s\n", resp.Status)
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
