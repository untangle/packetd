package predicttrafficsvc

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/untangle/packetd/services/logger"
	"github.com/untangle/packetd/services/overseer"
)

// IPPROTO_ICMP is ip protocol 1
const IPPROTO_ICMP = 1

// cloudAPIEndpoint is the URL of the cloud endpoint
const cloudAPIEndpoint = "https://classify.untangle.com"

// authRequestKey contains the authrequestkey for authenticating against the cloud API endpoint
const authRequestKey = "4E6FAB77-B2DF-4DEA-B6BD-2B434A3AE981"

// positiveCacheTime sets how long we store good prediction results received from the cloud
const positiveCacheTime = time.Second * 86400

// troubledCacheTime sets how long we store unknown result when there is an error or parsing the cloud response
const troubledCacheTime = time.Second * 3600

// negativeCacheTime sets how long we store an unknown result when we encouter a network error talking to the cloud
const negativeCacheTime = time.Second * 60

// longCacheTime sets how long we store a restult that we essentially want to be permanant
const longCacheTime = time.Second * 60 * 60 * 24 * 365

// cloud request timeout
const cloudLookupTimeout = time.Millisecond * 500

// ClassifiedTraffic struct contains the API response data
type ClassifiedTraffic struct {
	ID           string  `json:"Application"`
	Name         string  `json:"ApplicationName"`
	Confidence   float32 `json:"Confidence"`
	ProtoChain   string  `json:"Protocolchain"`
	Productivity uint8   `json:"ApplicationProductivity"`
	Risk         uint8   `json:"ApplicationRisk"`
	Category     string  `json:"ApplicationCategory"`
}

// trafficHolder struct contains the cached traffic data and the expiration time
// it also includes a mutex and waitgroup used to synchronize multiple threads
// that request prediction for the same ip+port+protocol at the same time
type trafficHolder struct {
	trafficData *ClassifiedTraffic
	expireTime  time.Time
	waitGroup   sync.WaitGroup
	dataLocker  sync.RWMutex
}

// unknownTrafficItem is a pointer for unknown traffic
var unknownTrafficItem = &ClassifiedTraffic{ID: "Unknown", Name: "Unknown", Confidence: 0, ProtoChain: "Unknown", Productivity: 0, Risk: 0, Category: "Unknown"}

// icmpTrafficItem is a pointer for icmp traffic
var icmpTrafficItem = &ClassifiedTraffic{ID: "ICMP", Name: "ICMP", Confidence: 100, ProtoChain: "/IP/ICMP", Productivity: 3, Risk: 4, Category: "Network Monitoring"}

// classifiedTrafficCache is a map of ClassifiedTraffic pointer structs
var classifiedTrafficCache map[string]*trafficHolder

// trafficMutex is used to prevent multiple writes into the cache map
var trafficMutex sync.RWMutex

// shutdownChannel is used when destroying the service to shutdown the cache cleaning utility safely
var shutdownChannel = make(chan bool)

var transport *http.Transport
var client *http.Client

// Startup is called during service startup
func Startup() {
	logger.Info("Starting up the traffic classification service\n")

	classifiedTrafficCache = make(map[string]*trafficHolder)
	go cleanStaleTrafficItems()

	// Build a persistent transport based on the http.DefaultTransport but with
	// shorter timeouts and idle settings that will keep the connections alive
	// to allow for quick transactions. We set maximum idle to the number of
	// CPU's to allow one active connection per nfqueue thread.
	transport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   cloudLookupTimeout,
			KeepAlive: 300 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          runtime.NumCPU(),
		MaxIdleConnsPerHost:   runtime.NumCPU(),
		IdleConnTimeout:       300 * time.Second,
		TLSHandshakeTimeout:   cloudLookupTimeout,
		ExpectContinueTimeout: 0,
	}

	client = &http.Client{
		Timeout:   cloudLookupTimeout,
		Transport: transport,
	}
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
func GetTrafficClassification(ipAdd net.IP, port uint16, protoID uint8) *ClassifiedTraffic {
	var holder *trafficHolder
	var result *ClassifiedTraffic
	var cachetime time.Duration
	var mapKey = formMapKey(ipAdd, port, protoID)

	// lock the cache mutex and get the traffic holder
	trafficMutex.RLock()
	holder = classifiedTrafficCache[mapKey]
	trafficMutex.RUnlock()

	// If we found the holder unlock the map. If not, we create and store the holder
	// and then send the request to the cloud. We also increment the waitgroup so
	// other threads trying to do the same lookup can wait for our reply rather
	// rather than generating multiple cloud requests for the same information
	if holder != nil {
		logger.Trace("Loading prediction for %s\n", mapKey)
	} else {
		trafficMutex.Lock()

		logger.Trace("Fetching prediction for %s\n", mapKey)
		holder = new(trafficHolder)
		holder.waitGroup.Add(1)
		classifiedTrafficCache[mapKey] = holder
		trafficMutex.Unlock()

		if protoID == IPPROTO_ICMP {
			// the cloud only provides tcp and udp predictions
			// so hardcode icmp results
			result = icmpTrafficItem
			cachetime = longCacheTime
		} else {
			// send the request to the cloud
			result, cachetime = sendClassifyRequest(ipAdd, port, protoID)
		}

		// safely store the response and the cache time returned from the lookup
		holder.dataLocker.Lock()
		holder.expireTime = time.Now()
		holder.trafficData = result
		holder.expireTime.Add(cachetime)
		holder.dataLocker.Unlock()

		// clear the waitgroup to release other threads waiting for the response we just added
		holder.waitGroup.Done()
	}

	// at this point holder should have either been retrieved or created
	if holder == nil {
		logger.Crit("Logic error: nil traffic holder\n")
		return nil
	}

	// Wait until the prediction has been retrieved. This will only happen when two
	// or more sessions request prediction for the same ip+port+proto at the same time.
	// The first one will do the cloud lookup and the others will wait here.
	holder.waitGroup.Wait()

	holder.dataLocker.RLock()
	traffic := holder.trafficData
	holder.dataLocker.RUnlock()

	logger.Trace("Found prediction for %s - %v\n", mapKey, traffic)
	return traffic
}

// sendClassifyRequest will send the classification request to the API endpoint using the provided parameters
// It returns the classification result or nil along with how long the response should be cached
func sendClassifyRequest(ipAdd net.IP, port uint16, protoID uint8) (*ClassifiedTraffic, time.Duration) {
	requestURL := formRequestURL(ipAdd, port, protoID)
	logger.Debug("Prediction request: [%d]%s:%d\n", protoID, ipAdd.String(), port)

	overseer.AddCounter("traffic_prediction_cloud_api_lookup", 1)

	req, err := http.NewRequest("GET", requestURL, nil)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("AuthRequest", authRequestKey)
	req.Header.Add("Connection", "Keep-Alive")

	resp, err := client.Do(req)

	if err != nil {
		// timeout requests are handled differently
		if err.(net.Error).Timeout() {
			logger.Warn("%OC|Cloud API request to %s has timed out, error: %v\n", "traffic_prediction_cloud_api_timeout", 10, cloudAPIEndpoint, err)
			return unknownTrafficItem, negativeCacheTime
		}

		logger.Warn("%OC|Cloud API request to %s has failed, error details: %v\n", "traffic_prediction_cloud_api_failure", 10, cloudAPIEndpoint, err)
		return unknownTrafficItem, negativeCacheTime
	}

	// From the golang docs:
	// If the returned error is nil, the Response will contain a non-nil Body which the user is expected to close. If the
	// Body is not both read to EOF and closed, the Client's underlying RoundTripper (typically Transport) may not be
	// able to re-use a persistent TCP connection to the server for a subsequent "keep-alive" request.
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logger.Err("Error reading body of prediction request: %v\n", err)
		return unknownTrafficItem, negativeCacheTime
	}

	if resp.StatusCode != http.StatusOK {
		logger.Err("Error code returned for prediction request: %v\n", err)
		return unknownTrafficItem, troubledCacheTime
	}

	trafficResponse := new(ClassifiedTraffic)
	bodyString := string(bodyBytes)
	json.Unmarshal([]byte(bodyString), &trafficResponse)
	logger.Debug("Prediction response: [%d]%s:%d = %v\n", protoID, ipAdd.String(), port, *trafficResponse)
	return trafficResponse, positiveCacheTime
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
	logger.Debug("Starting traffic cache clean up...\n")
	var counter int
	nowtime := time.Now()

	trafficMutex.Lock()
	defer trafficMutex.Unlock()

	for key, val := range classifiedTrafficCache {
		// ignore entries that are not yet expired
		if nowtime.Before(val.expireTime) {
			continue
		}

		logger.Debug("Removing %s from cache due to lapsed TTL\n", key)
		counter++
		delete(classifiedTrafficCache, key)
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
