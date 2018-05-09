package geoip

import (
	"io"
	"os"
	"sync"
	"net/http"
	"compress/gzip"
	"github.com/untangle/packetd/support"
	"github.com/oschwald/geoip2-golang"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/untangle/packetd/conndict"
)

var geodb *geoip2.Reader

/*---------------------------------------------------------------------------*/
func Plugin_Startup(childsync *sync.WaitGroup) {
	support.LogMessage("Plugin_Startup(%s) has been called\n", "geoip")

	var filename string

	// start by looking for the NGFW city database file
	filename = "/var/cache/untangle-geoip/GeoLite2-City.mmdb"
	_, err := os.Stat(filename)

	// if not found look for the MicroFW country database file
	if (os.IsNotExist(err)) {
		filename = "/tmp/GeoLite2-Country.mmdb" // TODO - where should this file be stored?
		_, err := os.Stat(filename);

		// if still not found download the country database
		if (os.IsNotExist(err)) {
			databaseDownload(filename)
		}
	}

	db, err := geoip2.Open(filename)
	if err != nil {
		support.LogMessage("Unable to load GeoIP Database: %s\n", err)
	} else {
		support.LogMessage("Loading GeoIP Database: %s\n", filename)
		geodb = db
	}

	childsync.Add(1)
}

/*---------------------------------------------------------------------------*/
func Plugin_Goodbye(childsync *sync.WaitGroup) {
	support.LogMessage("Plugin_Goodbye(%s) has been called\n", "geoip")
	geodb.Close()
	childsync.Done()
}

/*---------------------------------------------------------------------------*/
func databaseDownload(filename string) {
	support.LogMessage("Downloading GeoIP Database\n");

	// Get the GeoIP database from MaxMind
	resp, err := http.Get("http://geolite.maxmind.com/download/geoip/database/GeoLite2-Country.mmdb.gz")
	if err != nil { return }
	defer resp.Body.Close()

	// Check server response
	if (resp.StatusCode != http.StatusOK) {
		support.LogMessage("Download failure: %s\n",resp.Status)
		return
	}

	// Create a reader for the compressed data
	reader, err := gzip.NewReader(resp.Body)
	if err != nil { return }
	defer reader.Close()

	// Create the output file
	writer, err := os.Create(filename)
	if err != nil { return }
	defer writer.Close()

	// Write the uncompressed database to the file
	io.Copy(writer, reader)
}

/*---------------------------------------------------------------------------*/
func Plugin_netfilter_handler(ch chan<- int32, buffer []byte, length int, ctid uint) {
	var SrcCode string = "XX"
	var DstCode string = "XX"

	support.LogMessage("GEOIP RECEIVED %d BYTES\n", length)
	packet := gopacket.NewPacket(buffer, layers.LayerTypeIPv4, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		addr := ipLayer.(*layers.IPv4)
		SrcRecord, err := geodb.City(addr.SrcIP)
		if (err == nil) && (len(SrcRecord.Country.IsoCode) != 0) {
			SrcCode = SrcRecord.Country.IsoCode
			support.LogMessage("SRC: %s = %s\n", addr.SrcIP, SrcCode)
		}
		DstRecord, err := geodb.City(addr.DstIP)
		if (err == nil) && (len(DstRecord.Country.IsoCode) != 0) {
			DstCode = DstRecord.Country.IsoCode
			support.LogMessage("DST: %s = %s\n", addr.DstIP, DstCode)
		}
	}

	errc := conndict.Set_pair("Client Country", SrcCode, ctid)
	if (errc != nil) {
		support.LogMessage("Set_pair(client) ERROR: %s\n", errc)
	} else {
		support.LogMessage("Set_pair(client) %d = %s\n",ctid, SrcCode)
	}

	errs := conndict.Set_pair("Server Country", DstCode, ctid)
	if (errs != nil) {
		support.LogMessage("Set_pair(server) ERROR: %s\n", errs)
	} else {
		support.LogMessage("Set_pair(server) %d = %s\n",ctid, DstCode)
	}

	ch <- 4
}

/*---------------------------------------------------------------------------*/
