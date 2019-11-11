package predicttrafficsvc

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/untangle/packetd/services/logger"
)

// cloudAPIHost and cloudAPIPort specify the API endpoint and they are both
// strings to make it easier to use them together in the Dial function
const cloudAPIHost = "labs.untangle.com"
const cloudAPIPort = "443"

// number of seconds to wait before timeout of connection Write and Read calls
const cloudAPITimeout = 10

// authRequestKey contains the authrequestkey for authenticating against the cloud API endpoint
const authRequestKey = "4E6FAB77-B2DF-4DEA-B6BD-2B434A3AE981"

// cacheTTL determines how long the cache items should persist (86400 is 24 hours)
const cacheTTL = 86400

// predictionRequest contains the fields we submit to the prediction endpoint
// and the result channel where the response should be written
type predictionRequest struct {
	ipAddress     string
	ipProtocol    uint8
	servicePort   uint16
	resultChannel chan *ClassifiedTraffic
	hitCount      int
}

// number of times to retry prediction lookup after failure due to connection problems
// this will be calculated as CPU_COUNT + 1 to handle the worst case scenario where all
// of the active connections timeout at the same time and a request just happens to
// be tried by all of them.
var cloudAPIRetry int

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

// CachedTrafficItem struct contains the cached traffic data and last access time (in Unix time)
type CachedTrafficItem struct {
	TrafficData *ClassifiedTraffic
	lastAccess  int64
}

// unknownTrafficItem is a pointer for unknown traffic
var unknownTrafficItem = &ClassifiedTraffic{ID: "Unknown", Name: "Unknown", Confidence: 0, ProtoChain: "Unknown", Productivity: 0, Risk: 0, Category: "Unknown"}

// classifiedTrafficCache is a map of ClassifiedTraffic pointer structs
var classifiedTrafficCache map[string]*CachedTrafficItem

// trafficMutex is used to prevent multiple writes into the cache map
var trafficMutex sync.Mutex

// shutdownChannel is used when destroying the service to shutdown the cache cleaning utility safely
var shutdownChannel = make(chan bool)

// requestChannel is polled by all of the prediction worker goroutines
var requestChannel = make(chan *predictionRequest, 16)

// workerGroup is used to allow the Shutdown function to wait for all worker goroutines to finish
var workerGroup sync.WaitGroup

// Startup is called during service startup
func Startup() {
	logger.Info("Starting up the traffic classification service\n")
	classifiedTrafficCache = make(map[string]*CachedTrafficItem)

	// start the cleanup goroutine
	workerGroup.Add(1)
	go cleanStaleTrafficItems()

	cloudAPIRetry = (runtime.NumCPU() + 1)

	// create one worker goroutine for each CPU for processing prediction requests
	for x := 0; x < runtime.NumCPU(); x++ {
		workerGroup.Add(1)
		go lookupWorker(x)
	}
}

// Shutdown is called to handle service shutdown
func Shutdown() {
	logger.Info("Stopping up the traffic classification service\n")

	// close the main shutdown channel to signal all worker goroutines
	close(shutdownChannel)

	// there is no way to select on a WaitGroup so we use an anonymous goroutine to do
	// the waiting and close the finished channel to signal the final cleanup select
	finished := make(chan bool)
	go func() {
		workerGroup.Wait()
		close(finished)
	}()

	select {
	case <-finished:
		logger.Info("Successful shutdown of traffic prediction cleanup\n")
	case <-time.After(10 * time.Second):
		logger.Warn("Failed to properly shutdown traffic prediction cleanup\n")
	}
}

// GetTrafficClassification will retrieve the predicted traffic classification, first from memory cache then from cloud API endpoint
func GetTrafficClassification(ipAdd net.IP, port uint16, protoID uint8) *ClassifiedTraffic {

	if len(authRequestKey) == 0 {
		logger.Err("AuthRequestKey is not configured for traffic prediction service\n")
		return nil
	}

	var classifiedTraffic *ClassifiedTraffic
	var mapKey = formMapKey(ipAdd, port, protoID)

	// first see if we have the prediction in the cache
	trafficMutex.Lock()
	classifiedTraffic = findCachedTraffic(mapKey)
	trafficMutex.Unlock()

	// not found in the cache so create a predictionRequest, push it onto the
	// requestChannel and wait for the results on the resultChannel
	if classifiedTraffic == nil {
		xmit := new(predictionRequest)
		xmit.ipAddress = ipAdd.String()
		xmit.servicePort = port
		xmit.ipProtocol = protoID
		xmit.hitCount = 0
		xmit.resultChannel = make(chan *ClassifiedTraffic, 1)
		requestChannel <- xmit
		classifiedTraffic = <-xmit.resultChannel
		close(xmit.resultChannel)
		storeCachedTraffic(mapKey, classifiedTraffic)
	}

	// If this is still nil then API isn't responding or we are unable to access the data
	if classifiedTraffic == nil {
		logger.Debug("Unable to predict traffic information for requested IP, creating empty cache item: %v Port: %d Protocol: %d\n", ipAdd, port, protoID)
		storeCachedTraffic(mapKey, unknownTrafficItem)
		return nil
	}

	return classifiedTraffic
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

// findCachedTraffic will search the cache for a key of the traffic item, sets the last access time and returns the data
func findCachedTraffic(mapKey string) *ClassifiedTraffic {
	trafficCacheItem := classifiedTrafficCache[mapKey]
	if trafficCacheItem != nil {
		logger.Debug("Found a cache item: %v last access time %d\n", trafficCacheItem.TrafficData, trafficCacheItem.lastAccess)
		classifiedTrafficCache[mapKey].lastAccess = time.Now().Unix()
		return trafficCacheItem.TrafficData
	}

	return nil
}

// storeCachedTraffic will store a new cache item into the classified traffic cache
func storeCachedTraffic(mapKey string, classTraff *ClassifiedTraffic) {
	logger.Debug("Storing a cache item for key: %s\n", mapKey)
	trafficMutex.Lock()
	var newTrafficItem = new(CachedTrafficItem)
	newTrafficItem.TrafficData = classTraff
	newTrafficItem.lastAccess = time.Now().Unix()
	classifiedTrafficCache[mapKey] = newTrafficItem
	trafficMutex.Unlock()
}

// cleanStaleTrafficItems is a periodic task to clean the stale traffic items
func cleanStaleTrafficItems() {
	// increment the wait group to allow for clean shutdown
	for {
		select {
		case <-shutdownChannel:
			workerGroup.Done()
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

// lookupWorker is the main goroutine function for handling prediction requests
// each instance will establish a persistent TLS connection to the cloud service
// and use that connection to process requests pulled from the request channel
func lookupWorker(index int) {
	var buffer []byte
	var conn *tls.Conn
	var goodbye bool
	var err error

	logger.Info("Lookup worker %d has started\n", index)

	// create a buffer to hold the data received from the server
	buffer = make([]byte, 1024)

	// create a persistent connection to the cloud server
	conn, err = tls.Dial("tcp", cloudAPIHost+":"+cloudAPIPort, nil)
	if err != nil {
		logger.Err("Error calling Dial(%d): %v\n", index, err)
		return
	}

	// manually trigger the TLS handshake
	err = conn.Handshake()
	if err != nil {
		logger.Err("Error calling Handshake(%d): %v\n", index, err)
		return
	}

	// process requests until the goodbye flag is set by the shutdown channel
	// The trafficLookup function will return true if a connection problem was
	// detected so we use that to trigger reconnect. If the reconnect fails here
	// the next time we try to handle a request the broken connection will be
	// detected by trafficLookup which will trigger another reconnect attempt.
	// When trafficLookup does indicate a connection problem it will NOT write
	// to the result channel and we push the request back on the request channel
	// allowing another lookup attempt.
	for goodbye == false {
		select {
		case request := <-requestChannel:
			// if this request has exceeded the retry count send the unknown result
			if request.hitCount > cloudAPIRetry {
				logger.Warn("Exceeded retry count for %v\n", request)
				request.resultChannel <- unknownTrafficItem
				continue
			}
			problem := trafficLookup(conn, buffer, request)
			if problem == true {
				// couldn't talk to the server so increment the hit count and push the request back on the channel for another try
				request.hitCount++
				requestChannel <- request
				logger.Warn("Lookup worker %d recycling connection\n", index)
				conn.Close()
				conn, err = tls.Dial("tcp", cloudAPIHost+":"+cloudAPIPort, nil)
				if err != nil {
					logger.Err("Error calling Dial(%d): %v\n", index, err)
					continue
				}
				err = conn.Handshake()
				if err != nil {
					logger.Err("error calling Handhake(%d): %v\n", index, err)
					continue
				}
			}
		case <-shutdownChannel:
			goodbye = true
		}
	}

	conn.Close()
	logger.Info("Lookup worker %d has finished\n", index)
	workerGroup.Done()
}

// trafficLookup is called to submit a prediction request to the cloud server
// We us the connection we are passed for communication and we put the classification
// result in the channel included in the request object. If we detect a connection error
// we return true to the caller to trigger socket recycle, otherwise we return false
func trafficLookup(conn *tls.Conn, buffer []byte, request *predictionRequest) bool {
	var message strings.Builder
	var reply string
	var err error
	var count int

	header := fmt.Sprintf("GET /v1/traffic?ip=%s&port=%d&protocolId=%d HTTP/1.1", request.ipAddress, request.servicePort, request.ipProtocol)
	logger.Debug("Prediction request: %s\n", header)

	// create the GET request
	message.WriteString(header + "\r\n")
	message.WriteString("Host: " + cloudAPIHost + "\r\n")
	message.WriteString("User-Agent: Untangle Packet Daemon\r\n")
	message.WriteString("Content-Type: application/json\r\n")
	message.WriteString("AuthRequest: " + authRequestKey + "\r\n")
	message.WriteString("Connection: Keep-Alive\r\n")
	message.WriteString("\r\n")

	// write the request to the server
	conn.SetWriteDeadline(time.Now().Add(cloudAPITimeout * time.Second))
	count, err = conn.Write([]byte(message.String()))
	if err != nil {
		logger.Err("Error writing to server: %v\n", err)
		return true
	}

	if count != message.Len() {
		logger.Warn("Truncation writing to server. Have:%d Sent:%d\n", message.Len(), count)
		return true
	}

	logger.Trace("Transmitted %d bytes to server...\n%v\n", count, message.String())

	// reset our string builder so we can use it to store the server response
	message.Reset()

	// read from the server until we get a complete response or we timeout
	for {
		conn.SetReadDeadline(time.Now().Add(cloudAPITimeout * time.Second))
		count, err = conn.Read(buffer)
		if err != nil {
			logger.Err("Error reading from server: %v\n", err)
			return true
		}

		// make sure we got something from the server
		if count < 1 {
			continue
		}

		// append the data we received to the message buffer
		message.Write(buffer[:count])
		reply = message.String()

		// if we don't find the header/end body/top go back for more data
		if strings.Index(reply, "\r\n\r\n") < 0 {
			continue
		}

		// if the last character isn't the final JSON bracket go back for more data
		if reply[message.Len()-1] != '}' {
			continue
		}

		// FIXME - the cleanest way to ensure we have the full response would be to find
		// Content-Length in the header and verify we get a response body of the indicated
		// size. That's a lot of extra parsing and probably overkill. I have yet to see the
		// full reply need more than a single read, so the simple checks above should be fine.

		// we seem to have a valid response so break out of the read loop
		break
	}

	logger.Trace("Received %d bytes from server...\n%s\n", count, reply)

	// scan the first line of the response for the protocol, code, and status
	// which should be something like: HTTP/1.1 200 OK
	var webProto string
	var webCode int
	var webStat string
	_, err = fmt.Sscanf(reply, "%s %d %s", &webProto, &webCode, &webStat)
	if err != nil {
		logger.Err("Error scanning status line: %v\n", err)
		request.resultChannel <- unknownTrafficItem
		return false
	}

	// if status code is something other than success put unknown in the result channel
	if webCode != 200 {
		logger.Err("Error returned from server: %d %s\n", webCode, webStat)
		request.resultChannel <- unknownTrafficItem
		return false
	}

	// good response so look for <CR><LF><CR><LF> which marks the end of the
	// response header and the beginning of the response body
	payload := strings.Index(reply, "\r\n\r\n")
	if payload < 0 {
		logger.Err("Unable to locate response body\n")
		request.resultChannel <- unknownTrafficItem
		return false
	}

	// found the start of the response body so use the payload offset
	// and the receive count to extrat the JSON in the reply
	trafficResponse := new(ClassifiedTraffic)
	json.Unmarshal(buffer[payload+4:count], trafficResponse)
	logger.Debug("Prediction response: %v\n", trafficResponse)
	request.resultChannel <- trafficResponse
	return false
}
