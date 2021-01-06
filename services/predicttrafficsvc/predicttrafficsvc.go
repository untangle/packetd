package predicttrafficsvc

import (
	"bytes"
	"encoding/json"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/untangle/packetd/services/logger"
	"github.com/untangle/packetd/services/overseer"
	"github.com/untangle/packetd/services/settings"
)

// IPPROTO_ICMP is ip protocol 1
const IPPROTO_ICMP = 1

// the cloud server hostname or address
var cloudServerAddress = "192.168.222.13"

// the cloud server port
var cloudServerPort = 21818

// cloud request timeout
const cloudLookupTimeout = time.Millisecond * 500

// positiveCacheTime sets how long we store good prediction results received from the cloud
const positiveCacheTime = time.Second * 14400

// unknownCacheTime sets how long we store unknown prediction results received from the cloud
const unknownCacheTime = time.Second * 3600

// negativeCacheTime sets how long we store an unknown result when we encouter any error talking to the cloud
const negativeCacheTime = time.Second * 60

// longCacheTime sets how long we store a restult that we essentially want to be permanant
const longCacheTime = time.Second * 60 * 60 * 24 * 365

// ClassifiedTraffic struct contains the API response data
type ClassifiedTraffic struct {
	ID           string  `json:"ID"`
	Name         string  `json:"Name"`
	Confidence   uint8   `json:"Confidence"`
	ProtoChain   string  `json:"ProtoChain"`
	Productivity uint8   `json:"Productivity"`
	Risk         uint8   `json:"Risk"`
	Category     string  `json:"Category"`
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

var machineUID = "00000000-0000-0000-0000-000000000000"

// Startup is called during service startup
func Startup() {
	var err error

	logger.Info("Starting up the traffic classification service\n")

	machineUID, err = settings.GetUID()
	if err != nil {
		logger.Warn("Unable to read UID: %s\n", err.Error())
	}

	classifiedTrafficCache = make(map[string]*trafficHolder)
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
	var sock *net.UDPConn
	var txlen int
	var rxlen int
	var err error

	logger.Debug("Prediction request: [%d]%s:%d\n", protoID, ipAdd.String(), port)
	overseer.AddCounter("traffic_prediction_cloud_api_lookup", 1)


	// create a request string with the arguments and allocate the receive buffer
	txbuffer := formRequestString(ipAdd, port, protoID)
	rxbuffer := make([]byte, 1024)

	// resolve the server address and set the port
	addr := net.UDPAddr{
		IP:   net.ParseIP(cloudServerAddress),
		Port: cloudServerPort,
	}

	// create a UDP socket endpoint to the server
	sock, err = net.DialUDP("udp", nil, &addr)
	if err != nil {
		logger.Err("Error calling DialUDP: %v\n", err)
		return unknownTrafficItem, negativeCacheTime
	}

	// make sure the socket gets closed when we return
	defer sock.Close()

	// send the request to the server
	txlen, err = sock.Write(txbuffer)
	if err != nil {
		logger.Err("Error sending packet to server: %v\n", err)
		return unknownTrafficItem, negativeCacheTime
	}

	// make sure we sent the entire buffer
	if txlen != len(txbuffer) {
		logger.Err("Short transmit %d of %d bytes\n", txlen, len(txbuffer))
		return unknownTrafficItem, negativeCacheTime
	}

	// set the socket timeout and read the response
	sock.SetReadDeadline(time.Now().Add(cloudLookupTimeout))
	rxlen, err = sock.Read(rxbuffer)

	// for timeout or any other error we just return the unknown response
	if err != nil {
		logger.Err("Error reading from socket: %v\n", err)
		return unknownTrafficItem, negativeCacheTime
	}

	// parse the contents of the server response
	trafficResponse := new(ClassifiedTraffic)
	err = json.Unmarshal(rxbuffer[:rxlen], &trafficResponse)
	if err != nil {
		logger.Err("Error parsing server response: %v\n", err)
		return unknownTrafficItem, negativeCacheTime
	}

	logger.Debug("Prediction response: [%d]%s:%d = %v\n", protoID, ipAdd.String(), port, *trafficResponse)

	// for Unknown response return with the negative cache time
	if trafficResponse.ID == "Unknown" {
		return trafficResponse, unknownCacheTime
	}

	// for good response return with positive cache time
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

// formRequestString will build the prediction request string in the format required by the server
// version+guid+ipaddr+port+protocol
func formRequestString(ipAdd net.IP, port uint16, protoID uint8) []byte {
	var buffer bytes.Buffer

	buffer.WriteString("1+")
	buffer.WriteString(machineUID)
	buffer.WriteByte('+')
	buffer.WriteString(ipAdd.String())
	buffer.WriteByte('+')
	buffer.WriteString(strconv.Itoa(int(port)))
	buffer.WriteByte('+')
	buffer.WriteString(strconv.Itoa(int(protoID)))
	return buffer.Bytes()
}
