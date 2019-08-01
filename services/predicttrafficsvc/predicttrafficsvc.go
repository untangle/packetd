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

type ClassifiedTraffic struct {
	Application   string
	Confidence    float32
	ProtocolChain string
}

// I think if we used some kind of hashmap this could be faster
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

func GetTrafficClassification(ipAdd net.IP, port uint16, protoId uint8) {
	logger.Info("Checking map for existing data...\n")
	var classifiedTraffic *ClassifiedTraffic
	var mapKey = formMapKey(ipAdd, port, protoId)
	classifiedTraffic = findCachedTraffic(mapKey)
	if classifiedTraffic == nil {
		logger.Info("No cache items found, checking request against service endpoint...\n")
		requestUrl := formRequestUrl(ipAdd, port, protoId)

		logger.Info("URL for Get: %s\n", requestUrl)
		classifiedTraffic = sendClassifyRequest(requestUrl)

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

func sendClassifyRequest(requestUrl string) *ClassifiedTraffic {

	var trafficResponse *ClassifiedTraffic

	client := &http.Client{}

	req, err := http.NewRequest("GET", requestUrl, nil)
	req.Header.Add("Content-Type", "application/json")

	resp, err := client.Do(req)

	if err != nil {
		logger.Err("Found an error: %v\n", err)
		return nil

	} else {

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
		} else {
			return nil
		}
	}
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

func formRequestUrl(ipAdd net.IP, port uint16, protoId uint8) string {
	var cloudApiEndpoint = "https://labs.untangle.com"
	var bufferUrl bytes.Buffer
	bufferUrl.WriteString(cloudApiEndpoint)
	bufferUrl.WriteString("/v1/traffic?ip=")
	bufferUrl.WriteString(ipAdd.String())
	bufferUrl.WriteString("&port=")
	bufferUrl.WriteString(strconv.Itoa(int(port)))
	bufferUrl.WriteString("&protocolId=")
	bufferUrl.WriteString(strconv.Itoa(int(protoId)))
	return bufferUrl.String()
}

func formMapKey(ipAdd net.IP, port uint16, protoId uint8) string {
	var mapKey bytes.Buffer
	mapKey.WriteString(ipAdd.String())
	mapKey.WriteString("-")
	mapKey.WriteString(strconv.Itoa(int(port)))
	mapKey.WriteString("-")
	mapKey.WriteString(strconv.Itoa(int(protoId)))
	return mapKey.String()
}
