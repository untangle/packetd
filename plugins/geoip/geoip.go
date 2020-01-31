package geoip

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang"
	"github.com/untangle/packetd/services/dict"
	"github.com/untangle/packetd/services/dispatch"
	"github.com/untangle/packetd/services/logger"
	"github.com/untangle/packetd/services/reports"
	"github.com/untangle/packetd/services/settings"
)

const pluginName = "geoip"

var shutdownChannel = make(chan bool)
var geoDatabaseReader *geoip2.Reader
var geoMutex sync.Mutex
var privateIPBlocks []*net.IPNet

// PluginStartup is called to allow plugin specific initialization.
// We initialize an instance of the GeoIP engine using any existing
// database we can find, or we download if needed. We increment the
// argumented WaitGroup so the main process can wait for our shutdown function
// to return during shutdown.
func PluginStartup() {
	var filename string

	logger.Info("PluginStartup(%s) has been called\n", pluginName)

	geoMutex.Lock()
	defer geoMutex.Unlock()

	filename, valid := checkGeoFile()
	if valid == false {
		databaseDownload(filename)
	}

	db, err := geoip2.Open(filename)
	if err != nil {
		logger.Warn("Unable to load GeoIP Database: %s\n", err)
	} else {
		logger.Info("Loading GeoIP Database: %s\n", filename)
		geoDatabaseReader = db
	}

	for _, cidr := range []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 unique local addr
	} {
		_, block, _ := net.ParseCIDR(cidr)
		privateIPBlocks = append(privateIPBlocks, block)
	}

	go downloadTask()
	dispatch.InsertNfqueueSubscription(pluginName, dispatch.GeoipPriority, PluginNfqueueHandler)
}

// PluginShutdown is called when the daemon is shutting down. We close our
// GeoIP engine and call done for the argumented WaitGroup to let the main
// process know we're finished.
func PluginShutdown() {
	logger.Info("PluginShutdown(%s) has been called\n", pluginName)

	shutdownChannel <- true

	select {
	case <-shutdownChannel:
		logger.Info("Successful shutdown of downloadTask\n")
	case <-time.After(10 * time.Second):
		logger.Warn("Failed to properly shutdown downloadTask\n")
	}

	geoMutex.Lock()
	defer geoMutex.Unlock()

	if geoDatabaseReader != nil {
		geoDatabaseReader.Close()
		geoDatabaseReader = nil
	}
}

// PluginNfqueueHandler is called to handle nfqueue packet data. We extract
// the source and destination IP address from the packet, lookup the GeoIP
// country code for each, and store them in the conntrack dictionary.
func PluginNfqueueHandler(mess dispatch.NfqueueMessage, ctid uint32, newSession bool) dispatch.NfqueueResult {
	var result dispatch.NfqueueResult

	// release immediately as we only care about the first packet
	dispatch.ReleaseSession(mess.Session, pluginName)

	// we only do the lookup for new sessions
	if !newSession {
		return result
	}

	geoMutex.Lock()
	defer geoMutex.Unlock()

	// we start by setting both the client and server country to XU for unknown
	var clientCountry = "XU"
	var serverCountry = "XU"
	var srcAddr net.IP
	var dstAddr net.IP

	if mess.IP6Layer != nil {
		srcAddr = mess.IP6Layer.SrcIP
		dstAddr = mess.IP6Layer.DstIP
	}

	if mess.IP4Layer != nil {
		srcAddr = mess.IP4Layer.SrcIP
		dstAddr = mess.IP4Layer.DstIP
	}

	// first we check to see if the source or destination addresses are
	// in private address blocks and if so assign the XL local country code

	if srcAddr != nil && isPrivateIP(srcAddr) {
		clientCountry = "XL"
	}

	if dstAddr != nil && isPrivateIP(dstAddr) {
		serverCountry = "XL"
	}

	// if we have a good database and good addresses and the country
	// is still unknown we do the database lookup

	if geoDatabaseReader != nil && srcAddr != nil && clientCountry == "XU" {
		SrcRecord, err := geoDatabaseReader.City(srcAddr)
		if (err == nil) && (len(SrcRecord.Country.IsoCode) != 0) {
			clientCountry = SrcRecord.Country.IsoCode
		}
	}

	if geoDatabaseReader != nil && dstAddr != nil && serverCountry == "XU" {
		DstRecord, err := geoDatabaseReader.City(dstAddr)
		if (err == nil) && (len(DstRecord.Country.IsoCode) != 0) {
			serverCountry = DstRecord.Country.IsoCode
		}
	}

	logger.Debug("SRC: %v = %s ctid:%d\n", srcAddr, clientCountry, ctid)
	logger.Debug("DST: %v = %s ctid:%d\n", dstAddr, serverCountry, ctid)

	dict.AddSessionEntry(ctid, "client_country", clientCountry)
	dict.AddSessionEntry(ctid, "server_country", serverCountry)
	mess.Session.PutAttachment("client_country", clientCountry)
	mess.Session.PutAttachment("server_country", serverCountry)

	logEvent(mess.Session, clientCountry, serverCountry)

	return result
}

func isPrivateIP(ip net.IP) bool {
	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// checkGeoFile determines the location and validity of the MaxMind GeoIP database file
func checkGeoFile() (string, bool) {
	var filename string
	var fileinfo os.FileInfo
	var err error

	// start by looking where the geoip-database package stores the file
	filename = "/usr/share/geoip/GeoLite2-Country.mmdb"
	if fileinfo, err = os.Stat(filename); err != nil {
		// not found so default to the temporary directory
		filename = "/tmp/GeoLite2-Country.mmdb"
		if fileinfo, err = os.Stat(filename); err != nil {
			// still not found so clear fileinfo to force download
			fileinfo = nil
		}
	}

	// if we can't get the file info return invalid flag
	if fileinfo == nil {
		return filename, false
	}

	// if the file exists but is empty return invalid flag
	if fileinfo.Size() == 0 {
		return filename, false
	}

	filetime := fileinfo.ModTime().Unix()
	currtime := time.Now().Unix()

	// if the file we found is less than 30 days old go ahead and use it
	if (filetime + (86400 * 30)) > currtime {
		return filename, true
	}

	// we found a file but it is stale so return invalid flag
	return filename, false
}

// databaseDownload will download the MaxMind GeoLite2 country database file
func databaseDownload(filename string) {
	var uid string
	var err error

	logger.Info("Starting GeoIP database download: %s\n", filename)

	// Make sure the target directory exists
	marker := strings.LastIndex(filename, "/")

	// Get the index of the last slash so we can isolate the path and create the directory
	if marker > 0 {
		os.MkdirAll(filename[0:marker], 0755)
	}

	// Get our UID so we can pass it to the download server
	uid, err = settings.GetUID()
	if err != nil {
		uid = "00000000-0000-0000-0000-000000000000"
		logger.Warn("Unable to read UID: %s - Using all zeros\n", err.Error())
	}

	// Download the GeoIP country database which is much smaller than the city version
	target := fmt.Sprintf("https://downloads.untangle.com/download.php?resource=geoipCountry&uid=%s", uid)
	resp, err := http.Get(target)
	if err != nil {
		logger.Warn("Download error: %v\n", err)
		return
	}
	defer resp.Body.Close()

	// Check server response
	if resp.StatusCode != http.StatusOK {
		logger.Warn("Download failure: %s\n", resp.Status)
		return
	}

	// Create a reader for the compressed data
	zipReader, err := gzip.NewReader(resp.Body)
	if err != nil {
		logger.Warn("Error calling gzip.NewReader(): %v\n", err)
		return
	}
	defer zipReader.Close()

	// Create a tar reader using the uncompressed data stream
	tarReader := tar.NewReader(zipReader)

	// Create the file where we'll store the extracted database
	writer, err := os.Create(filename)
	if err != nil {
		logger.Warn("Unable to write database file: %s\n", filename)
		return
	}

	var goodfile = false

	for {
		// get the next entry in the archive
		header, err := tarReader.Next()

		// break out of the loop on end of file
		if err == io.EOF {
			break
		}

		// log any other errors and break out of the loop
		if err != nil {
			logger.Crit("Error extracting database file: %v\n", err)
			break
		}

		// ignore everything that is not a regular file
		if header.Typeflag != tar.TypeReg {
			continue
		}

		// ignore everything except the actual database file
		if !strings.HasSuffix(header.Name, "GeoLite2-Country.mmdb") {
			continue
		}

		// found the database so write to the output file, set the goodfile flag, and break
		io.Copy(writer, tarReader)
		goodfile = true
		logger.Info("Finished GeoIP database download\n")
		break
	}

	// close the output file
	writer.Close()

	// if the flag is not set the file is empty or garbage and must be deleted
	if goodfile == false {
		os.Remove(filename)
	}
}

// logEvent logs an update event that updates the *_country columns
// provide the session, and the client and server country
func logEvent(session *dispatch.Session, clientCountry string, serverCountry string) {
	columns := map[string]interface{}{
		"session_id": session.GetSessionID(),
	}

	modifiedColumns := make(map[string]interface{})
	modifiedColumns["client_country"] = clientCountry
	modifiedColumns["server_country"] = serverCountry

	reports.LogEvent(reports.CreateEvent("session_geoip", "sessions", 2, columns, modifiedColumns))
}

// periodic task to check the database file and download a new version
// we check once per hour but checkGeoFile determines when the existing file is stale
func downloadTask() {
	for {
		select {
		case <-shutdownChannel:
			shutdownChannel <- true
			return
		case <-time.After(3600 * time.Second):
			filename, valid := checkGeoFile()

			// if the existing file is valid we are done
			if valid == true {
				break
			}

			// lock the mutex, close the existing database, and clear the reader
			geoMutex.Lock()
			geoDatabaseReader.Close()
			geoDatabaseReader = nil

			// download a fresh copy of the database
			databaseDownload(filename)

			// open the database
			db, err := geoip2.Open(filename)
			if err != nil {
				logger.Warn("Unable to open GeoIP Database: %s\n", err)
			} else {
				logger.Info("Loading GeoIP Database: %s\n", filename)
				geoDatabaseReader = db
			}

			// unlock the mutex
			geoMutex.Unlock()
		}
	}
}
