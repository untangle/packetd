package predicttrafficsvc

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"

	"github.com/untangle/packetd/services/logger"
)

// The ClassifiedTraffic struct contains the API response and cache data
type ClassifiedTraffic struct {
	Application   string
	Confidence    float32
	ProtocolChain string
}

// The classifiedTrafficCache is a map of ClassifiedTraffic structs
var classifiedTrafficCache map[string]*ClassifiedTraffic

// Startup is called during service startup
func Startup() {
	logger.Info("Starting up the traffic classification service")
	classifiedTrafficCache = make(map[string]*ClassifiedTraffic)

}

// Shutdown is called to handle service shutdown
func Shutdown() {
	logger.Info("Stopping up the traffic classification service")

}

// GetTrafficClassification will retrieve the predicted traffic classification, first from memory cache then from cloud API endpoint
func GetTrafficClassification(ipAdd net.IP, port uint16, protoID uint8) {
	logger.Info("Checking map for existing data...\n")
	var classifiedTraffic *ClassifiedTraffic
	var mapKey = formMapKey(ipAdd, port, protoID)
	classifiedTraffic = findCachedTraffic(mapKey)
	if classifiedTraffic == nil {
		logger.Info("No cache items found, checking request against service endpoint...\n")
		requestURL := formRequestURL(ipAdd, port, protoID)

		logger.Info("URL for Get: %s\n", requestURL)
		classifiedTraffic = sendClassifyRequest(requestURL)

		logger.Info("Adding this into the map... (popping a record if length is > n)\n")
		storeCachedTraffic(mapKey, classifiedTraffic)

	} else {
		logger.Info("Found a cache item!\n")
	}
	logger.Info("Current cache size: %d, current cache map: %v\n", len(classifiedTrafficCache), classifiedTrafficCache)

	logger.Info("Pass result to dict?\n")

	var b, err = json.Marshal(classifiedTraffic)

	if err != nil {
		logger.Err("Error marshaling json result: %v", err)
	}

	logger.Info("The current class result: %s\n", string(b))

}

func sendClassifyRequest(requestURL string) *ClassifiedTraffic {

	var trafficResponse *ClassifiedTraffic

	client := &http.Client{}

	req, err := http.NewRequest("GET", requestURL, nil)
	req.Header.Add("Content-Type", "application/json")

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
		logger.Info("Response body: %s\n", bodyString)

		json.Unmarshal([]byte(bodyString), &trafficResponse)

		return trafficResponse
	}

	return nil
}

func findCachedTraffic(mapKey string) *ClassifiedTraffic {
	trafficItem := classifiedTrafficCache[mapKey]
	if trafficItem != nil {
		return trafficItem
	}
	return nil
}

func storeCachedTraffic(mapKey string, classTraff *ClassifiedTraffic) {
	classifiedTrafficCache[mapKey] = classTraff

	if len(classifiedTrafficCache) > 500 {
		logger.Info("lots of stuff in cache, time to clean...\n")
		cleanupTraffic()
	}

}

func cleanupTraffic() {
	logger.Info("Cleaning up traffic...\n")
}

func formRequestURL(ipAdd net.IP, port uint16, protoID uint8) string {
	var cloudAPIEndpoint = "https://labs.untangle.com"
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
