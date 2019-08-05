package predicttrafficsvc

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/untangle/packetd/services/dict"
	"github.com/untangle/packetd/services/logger"
)

// cloudAPIEndpoint is the URL of the cloud endpoint
const cloudAPIEndpoint = "https://labs.untangle.com"

// authRequestKey contains the authrequestkey for authenticating against the cloud API endpoint
const authRequestKey = "4E6FAB77-B2DF-4DEA-B6BD-2B434A3AE981"

// cacheTTL determines how long the cache items should persist (86400 is 24 hours)
const cacheTTL = 86400

// ClassifiedTraffic struct contains the API response data
type ClassifiedTraffic struct {
	Application   string
	Confidence    float32
	ProtocolChain string
}

// CachedTrafficItem struct contains the cached traffic data and last access time (in Unix time)
type CachedTrafficItem struct {
	TrafficData *ClassifiedTraffic
	lastAccess  int64
}

// classifiedTrafficCache is a map of ClassifiedTraffic pointer structs
var classifiedTrafficCache map[string]*CachedTrafficItem

// trafficMutex is used to prevent multiple writes into the cache map
var trafficMutex sync.Mutex

// shutdownChannel is used when destroying the service to shutdown the cache cleaning utility safely
var shutdownChannel = make(chan bool)

// Startup is called during service startup
func Startup() {
	logger.Info("Starting up the traffic classification service\n")
	classifiedTrafficCache = make(map[string]*CachedTrafficItem)
	go cleanStaleTrafficItems()

}

// Shutdown is called to handle service shutdown
func Shutdown() {
	logger.Info("Stopping up the traffic classification service\n")

	shutdownChannel <- true

	select {
	case <-shutdownChannel:
		logger.Info("Successful shutdown of traffic prediction cleanup\n")
	case <-time.After(10 * time.Second):
		logger.Warn("Failed to properly shutdown traffic prediction cleanup\n")
	}
}

// GetTrafficClassification will retrieve the predicted traffic classification, first from memory cache then from cloud API endpoint
func GetTrafficClassification(ctid uint32, ipAdd net.IP, port uint16, protoID uint8) {

	if len(authRequestKey) == 0 {
		logger.Err("AuthRequestKey is not configured for traffic prediction service\n")
		return
	}

	logger.Debug("Checking map for existing data...\n")
	var classifiedTraffic *ClassifiedTraffic
	var mapKey = formMapKey(ipAdd, port, protoID)
	classifiedTraffic = findCachedTraffic(mapKey)
	if classifiedTraffic == nil {
		logger.Debug("No cache items found, checking request against service endpoint...\n")

		classifiedTraffic = sendClassifyRequest(ipAdd, port, protoID)

		logger.Debug("Adding this into the map...\n")
		storeCachedTraffic(mapKey, classifiedTraffic)

	}

	// If this is still nil then API isn't responding or we are unable to access the data
	if classifiedTraffic == nil {
		logger.Warn("Unable to predict traffic information for requested IP: %v Port: %d Protocol: %d\n", ipAdd, port, protoID)
		return
	}

	addPredictionToDict(ctid, classifiedTraffic)

	if logger.IsDebugEnabled() {

		logger.Debug("Current cache size: %d\n", len(classifiedTrafficCache))

		var b, err = json.Marshal(classifiedTraffic)

		if err != nil {
			logger.Err("Error marshaling json result: %v", err)
		}

		logger.Debug("The current class result: %s\n", string(b))
	}
}

// sendClassifyRequest will send the classification request to the API endpoint using the provided parameters
func sendClassifyRequest(ipAdd net.IP, port uint16, protoID uint8) *ClassifiedTraffic {

	var trafficResponse *ClassifiedTraffic
	client := &http.Client{}

	requestURL := formRequestURL(ipAdd, port, protoID)

	logger.Debug("URL for Get: %s\n", requestURL)

	req, err := http.NewRequest("GET", requestURL, nil)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("AuthRequest", authRequestKey)

	resp, err := client.Do(req)

	if err != nil {
		logger.Err("Found an error: %v\n", err)
		return nil
	}

	if resp.StatusCode == http.StatusOK {
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			logger.Err("Error reading body: %v", err)
			return nil
		}
		bodyString := string(bodyBytes)
		logger.Debug("Response body: %s\n", bodyString)

		json.Unmarshal([]byte(bodyString), &trafficResponse)

		return trafficResponse
	}

	return nil
}

// findCachedTraffic will search the cache for a key of the traffic item, sets the last access time and returns the data
func findCachedTraffic(mapKey string) *ClassifiedTraffic {
	trafficCacheItem := classifiedTrafficCache[mapKey]
	if trafficCacheItem != nil {
		trafficMutex.Lock()
		logger.Debug("Found a cache item: %v last access time %d\n", trafficCacheItem.TrafficData, trafficCacheItem.lastAccess)
		classifiedTrafficCache[mapKey].lastAccess = time.Now().Unix()
		trafficMutex.Unlock()
		return trafficCacheItem.TrafficData
	}

	return nil
}

// storeCachedTraffic will store a new cache item into the classified traffic cache
func storeCachedTraffic(mapKey string, classTraff *ClassifiedTraffic) {

	trafficMutex.Lock()
	var newTrafficItem = new(CachedTrafficItem)
	newTrafficItem.TrafficData = classTraff
	newTrafficItem.lastAccess = time.Now().Unix()
	classifiedTrafficCache[mapKey] = newTrafficItem
	trafficMutex.Unlock()
}

// cleanStaleTrafficItems is a periodic task to clean the stale traffic items
func cleanStaleTrafficItems() {
	for {
		select {
		case <-shutdownChannel:
			shutdownChannel <- true
			return
		case <-time.After(30 * time.Minute):
			cleanupTrafficCache()
		}
	}
}

// cleanupTrafficCache iterates the entire map and cleans stale entries that have not been accessed within the TTL time
func cleanupTrafficCache() {
	logger.Debug("Cleaning up traffic...\n")
	var counter int
	nowtime := time.Now().Unix()

	trafficMutex.Lock()
	defer trafficMutex.Unlock()

	for key, val := range classifiedTrafficCache {
		if nowtime-val.lastAccess > cacheTTL {
			logger.Debug("Removing %s from cache due to lapsed TTL\n", key)
			counter++
			delete(classifiedTrafficCache, key)
		}
	}

	logger.Debug("Traffic Items Removed:%d Remaining:%d\n", counter, len(classifiedTrafficCache))
}

// formRequestURL will build the request URL
func formRequestURL(ipAdd net.IP, port uint16, protoID uint8) string {
	var bufferURL bytes.Buffer
	bufferURL.WriteString(cloudAPIEndpoint)
	bufferURL.WriteString("/v1/traffic?ip=")
	bufferURL.WriteString(ipAdd.String())
	bufferURL.WriteString("&port=")
	bufferURL.WriteString(strconv.Itoa(int(port)))
	bufferURL.WriteString("&protocolId=")
	bufferURL.WriteString(strconv.Itoa(int(protoID)))
	return bufferURL.String()
}

// formMapKey will build the mapkey used in the cache stores and lookups
func formMapKey(ipAdd net.IP, port uint16, protoID uint8) string {
	var mapKey bytes.Buffer
	mapKey.WriteString(ipAdd.String())
	mapKey.WriteString("-")
	mapKey.WriteString(strconv.Itoa(int(port)))
	mapKey.WriteString("-")
	mapKey.WriteString(strconv.Itoa(int(protoID)))
	return mapKey.String()
}

// addPredictionToDict will take a ClassifiedTraffic pointer and send the data to dict. Confidence is converted to a uint8 here (basically floors it)
func addPredictionToDict(ctid uint32, currentTraffic *ClassifiedTraffic) {
	logger.Debug("Sending prediction info to dict with ctid: %d\n", ctid)
	dict.AddSessionEntry(ctid, "predicted_application", currentTraffic.Application)
	dict.AddSessionEntry(ctid, "predicted_confidence", uint8(currentTraffic.Confidence))
	dict.AddSessionEntry(ctid, "predicted_protocolchain", currentTraffic.ProtocolChain)
}
