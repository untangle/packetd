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

const cloudAPIEndpoint = "https://labs.untangle.com"

const authRequestKey = ""

const cacheTTL = 8400

// The ClassifiedTraffic struct contains the API response data
type ClassifiedTraffic struct {
	Application   string
	Confidence    float32
	ProtocolChain string
}

// The CachedTrafficItem struct contains the cached item and last access time (in Unix time)
type CachedTrafficItem struct {
	TrafficData *ClassifiedTraffic
	lastAccess  int64
}

// The classifiedTrafficCache is a map of ClassifiedTraffic structs
var classifiedTrafficCache map[string]*CachedTrafficItem

var trafficMutex sync.Mutex

// Startup is called during service startup
func Startup() {
	logger.Info("Starting up the traffic classification service")
	classifiedTrafficCache = make(map[string]*CachedTrafficItem)

}

// Shutdown is called to handle service shutdown
func Shutdown() {
	logger.Info("Stopping up the traffic classification service")

}

// GetTrafficClassification will retrieve the predicted traffic classification, first from memory cache then from cloud API endpoint
func GetTrafficClassification(ctid uint32, ipAdd net.IP, port uint16, protoID uint8) {
	logger.Debug("Checking map for existing data...\n")
	var classifiedTraffic *ClassifiedTraffic
	var mapKey = formMapKey(ipAdd, port, protoID)
	classifiedTraffic = findCachedTraffic(mapKey)
	if classifiedTraffic == nil {
		logger.Debug("No cache items found, checking request against service endpoint...\n")
		requestURL := formRequestURL(ipAdd, port, protoID)

		logger.Debug("URL for Get: %s\n", requestURL)
		classifiedTraffic = sendClassifyRequest(requestURL)

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

func sendClassifyRequest(requestURL string) *ClassifiedTraffic {

	if len(authRequestKey) == 0 {
		logger.Err("AuthRequestKey is not configured for traffic prediction service")
		return nil
	}

	var trafficResponse *ClassifiedTraffic

	client := &http.Client{}

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

func storeCachedTraffic(mapKey string, classTraff *ClassifiedTraffic) {

	trafficMutex.Lock()
	var newTrafficItem = new(CachedTrafficItem)
	newTrafficItem.TrafficData = classTraff
	newTrafficItem.lastAccess = time.Now().Unix()
	classifiedTrafficCache[mapKey] = newTrafficItem
	trafficMutex.Unlock()

	if len(classifiedTrafficCache) > 500 {
		logger.Debug("Cleaning up the traffic classification cache...\n")
		cleanupTraffic()
	}

}

func cleanupTraffic() {
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

func formMapKey(ipAdd net.IP, port uint16, protoID uint8) string {
	var mapKey bytes.Buffer
	mapKey.WriteString(ipAdd.String())
	mapKey.WriteString("-")
	mapKey.WriteString(strconv.Itoa(int(port)))
	mapKey.WriteString("-")
	mapKey.WriteString(strconv.Itoa(int(protoID)))
	return mapKey.String()
}

func addPredictionToDict(ctid uint32, currentTraffic *ClassifiedTraffic) {
	logger.Debug("Sending prediction info to dict with ctid: %d\n", ctid)
	dict.AddSessionEntry(ctid, "predicted_application", currentTraffic.Application)
	dict.AddSessionEntry(ctid, "predicted_confidence", uint8(currentTraffic.Confidence))
	dict.AddSessionEntry(ctid, "predicted_protocolchain", currentTraffic.ProtocolChain)
}
