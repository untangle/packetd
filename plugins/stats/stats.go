package stats

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/c9s/goprocinfo/linux"
	"github.com/untangle/packetd/services/dict"
	"github.com/untangle/packetd/services/dispatch"
	"github.com/untangle/packetd/services/logger"
	"github.com/untangle/packetd/services/overseer"
	"github.com/untangle/packetd/services/reports"
	"github.com/untangle/packetd/services/settings"
)

const pluginName = "stats"
const interfaceStatLogIntervalSec = 10

var statsCollector [256]*Collector
var passiveCollector [256]*Collector
var activeCollector [256]*Collector
var jitterCollector [256]*Collector

var statsLocker [256]sync.RWMutex
var passiveLocker [256]sync.RWMutex
var activeLocker [256]sync.RWMutex
var jitterLocker [256]sync.RWMutex

var interfaceDetailMap map[string]*interfaceDetail
var interfaceDetailLocker sync.RWMutex

var interfaceMetricList [256]*interfaceMetric
var interfaceMetricLocker sync.Mutex

var interfaceHashString string
var interfaceHashLocker sync.Mutex

var interfaceStatsMap map[string]*linux.NetworkStat
var interfaceDiffMap map[string]*linux.NetworkStat
var interfaceDiffLocker sync.RWMutex

var interfaceChannel = make(chan bool, 1)
var pingerChannel = make(chan bool, 1)

type interfaceDetail struct {
	interfaceID int
	deviceName  string
	netAddress  string
	pingMode    int
	wanFlag     bool
}

type interfaceMetric struct {
	PingTimeout     uint64
	lastPingTimeout uint64
}

// PluginStartup function is called to allow plugin specific initialization.
func PluginStartup() {
	logger.Info("PluginStartup(%s) has been called\n", pluginName)

	for x := 0; x < 256; x++ {
		statsCollector[x] = CreateCollector()
		passiveCollector[x] = CreateCollector()
		activeCollector[x] = CreateCollector()
		jitterCollector[x] = CreateCollector()
		interfaceMetricList[x] = new(interfaceMetric)
	}

	interfaceStatsMap = make(map[string]*linux.NetworkStat)
	interfaceDiffMap = make(map[string]*linux.NetworkStat)

	loadInterfaceDetailMap()
	refreshActivePingInfo()

	// the first check will record current status used to check for changes in subsequent calls
	checkForInterfaceChanges()

	go interfaceTask()
	go pingerTask()

	dispatch.InsertNfqueueSubscription(pluginName, dispatch.StatsPriority, PluginNfqueueHandler)
}

// PluginShutdown function called when the daemon is shutting down.
func PluginShutdown() {
	logger.Info("PluginShutdown(%s) has been called\n", pluginName)

	interfaceChannel <- true

	select {
	case <-interfaceChannel:
		logger.Info("Successful shutdown of interfaceTask\n")
	case <-time.After(10 * time.Second):
		logger.Warn("Failed to properly shutdown interfaceTask\n")
	}

	pingerChannel <- true

	select {
	case <-pingerChannel:
		logger.Info("Successful shutdown of pingerTask\n")
	case <-time.After(10 * time.Second):
		logger.Warn("Failed to properly shutdown pingerTask\n")
	}
}

// PluginSignal is called to handle system signals
func PluginSignal(message syscall.Signal) {
	switch message {
	case syscall.SIGHUP:
		// reload the interface map and ping info and signal the pinger task to refresh the ICMP sockets
		loadInterfaceDetailMap()
		refreshActivePingInfo()
		pingerChannel <- false
	}
}

// PluginNfqueueHandler is called to handle nfqueue packet data.
func PluginNfqueueHandler(mess dispatch.NfqueueMessage, ctid uint32, newSession bool) dispatch.NfqueueResult {
	var result dispatch.NfqueueResult

	// we release by default unless logic below changes the flag
	result.SessionRelease = true

	// if this is a new session attach the current time
	if newSession {
		mess.Session.PutAttachment("stats_timer", time.Now())
		logHopCount(ctid, mess, "client_hops")
	}

	// ignore C2S packets but keep scanning until we get the first server response
	if mess.ClientToServer {
		result.SessionRelease = false
		return result
	}

	// get the hop count for the server
	logHopCount(ctid, mess, "server_hops")

	// We have a packet from the server so we calculate the latency as the
	// time elapsed since the first client packet was transmitted
	xmittime := mess.Session.GetAttachment("stats_timer")
	if xmittime == nil {
		logger.Warn("Missing stats_timer for session %d\n", ctid)
		return result
	}

	// We have a packet from the server so we calculate the latency as the
	// time elapsed sincethe first client packet was transmitted
	duration := time.Since(xmittime.(time.Time))
	interfaceID := mess.Session.GetServerInterfaceID()

	// ignore local traffic
	if interfaceID == 255 {
		return result
	}

	// count and ignore traffic to unknown interface
	if interfaceID == 0 {
		overseer.AddCounter("stats_unknown_interface", 1)
		return result
	}

	logger.Debug("Logging passive latency: %d, %v, %v ms\n", interfaceID, mess.Session.GetServerSideTuple().ServerAddress, (duration.Nanoseconds() / 1000000))

	statsLocker[interfaceID].Lock()
	passiveLocker[interfaceID].Lock()
	statsCollector[interfaceID].AddDataPointLimited(float64(duration.Nanoseconds())/1000000.0, 2.0)
	passiveCollector[interfaceID].AddDataPointLimited(float64(duration.Nanoseconds())/1000000.0, 2.0)
	statsLocker[interfaceID].Unlock()
	passiveLocker[interfaceID].Unlock()

	return result
}

func interfaceTask() {

	for {
		select {
		case <-interfaceChannel:
			interfaceChannel <- true
			return
		case <-time.After(time.Second * time.Duration(interfaceStatLogIntervalSec)):
			logger.Debug("Collecting interface statistics\n")
			collectInterfaceStats(interfaceStatLogIntervalSec)
		}
	}
}

// collectInterfaceStats gets the stats for every interface and then
// calculates and logs the difference since the last time it was called
func collectInterfaceStats(seconds uint64) {
	var statInfo *linux.NetworkStat
	var diffInfo *linux.NetworkStat
	var istats []InterfaceStatsJSON
	var interfaceID int

	procData, err := linux.ReadNetworkStat("/proc/net/dev")
	if err != nil {
		logger.Err("Error reading interface statistics:%v\n", err)
		return
	}

	for i := 0; i < len(procData); i++ {
		item := procData[i]

		// ignore loopback and dummy interfaces
		if item.Iface == "lo" || strings.HasPrefix(item.Iface, "dummy") {
			continue
		}

		// convert the interface name to the ID value
		interfaceID = getInterfaceIDValue(item.Iface)

		// negative return means we don't know the ID so ignore
		if interfaceID < 0 {
			logger.Debug("Skipping unknown interface: %s\n", item.Iface)
			continue
		}

		// create a new instance for the curr-last rate calculation object and lookup the current value object
		diffInfo = new(linux.NetworkStat)
		statInfo = interfaceStatsMap[item.Iface]

		if statInfo == nil {
			// if no entry for the interface use the existing values to create the entry
			statInfo = new(linux.NetworkStat)
			statInfo.Iface = item.Iface
			statInfo.RxBytes = item.RxBytes
			statInfo.RxPackets = item.RxPackets
			statInfo.RxErrs = item.RxErrs
			statInfo.RxDrop = item.RxDrop
			statInfo.RxFifo = item.RxFifo
			statInfo.RxFrame = item.RxFrame
			statInfo.RxCompressed = item.RxCompressed
			statInfo.RxMulticast = item.RxMulticast
			statInfo.TxBytes = item.TxBytes
			statInfo.TxPackets = item.TxPackets
			statInfo.TxErrs = item.TxErrs
			statInfo.TxDrop = item.TxDrop
			statInfo.TxFifo = item.TxFifo
			statInfo.TxColls = item.TxColls
			statInfo.TxCarrier = item.TxCarrier
			statInfo.TxCompressed = item.TxCompressed
			interfaceStatsMap[item.Iface] = statInfo
		} else {
			// found the interface entry so calculate the difference since last time
			diffInfo.Iface = item.Iface
			diffInfo.RxBytes = calculateDifference(statInfo.RxBytes, item.RxBytes)
			diffInfo.RxPackets = calculateDifference(statInfo.RxPackets, item.RxPackets)
			diffInfo.RxErrs = calculateDifference(statInfo.RxErrs, item.RxErrs)
			diffInfo.RxDrop = calculateDifference(statInfo.RxDrop, item.RxDrop)
			diffInfo.RxFifo = calculateDifference(statInfo.RxFifo, item.RxFifo)
			diffInfo.RxFrame = calculateDifference(statInfo.RxFrame, item.RxFrame)
			diffInfo.RxCompressed = calculateDifference(statInfo.RxCompressed, item.RxCompressed)
			diffInfo.RxMulticast = calculateDifference(statInfo.RxMulticast, item.RxMulticast)
			diffInfo.TxBytes = calculateDifference(statInfo.TxBytes, item.TxBytes)
			diffInfo.TxPackets = calculateDifference(statInfo.TxPackets, item.TxPackets)
			diffInfo.TxErrs = calculateDifference(statInfo.TxErrs, item.TxErrs)
			diffInfo.TxDrop = calculateDifference(statInfo.TxDrop, item.TxDrop)
			diffInfo.TxFifo = calculateDifference(statInfo.TxFifo, item.TxFifo)
			diffInfo.TxColls = calculateDifference(statInfo.TxColls, item.TxColls)
			diffInfo.TxCarrier = calculateDifference(statInfo.TxCarrier, item.TxCarrier)
			diffInfo.TxCompressed = calculateDifference(statInfo.TxCompressed, item.TxCompressed)

			// replace the current stats map object with the one returned from ReadNetworkStat
			interfaceStatsMap[item.Iface] = &item

			// calculate the difference for other metrics we track for each interface
			interfaceMetricLocker.Lock()
			metric := calculateMetrics(interfaceMetricList[interfaceID])
			interfaceMetricLocker.Unlock()

			// get copies of the three latency collectors
			statsLocker[interfaceID].RLock()
			combo := statsCollector[interfaceID].MakeCopy()
			statsLocker[interfaceID].RUnlock()

			passiveLocker[interfaceID].RLock()
			passive := passiveCollector[interfaceID].MakeCopy()
			passiveLocker[interfaceID].RUnlock()

			activeLocker[interfaceID].RLock()
			active := activeCollector[interfaceID].MakeCopy()
			activeLocker[interfaceID].RUnlock()

			jitterLocker[interfaceID].RLock()
			jitter := jitterCollector[interfaceID].MakeCopy()
			jitterLocker[interfaceID].RUnlock()

			istat := MakeInterfaceStatsJSON(interfaceID, combo.Latency1Min.Value, combo.Latency5Min.Value, combo.Latency15Min.Value)
			istats = append(istats, istat)

			logInterfaceStats(seconds, interfaceID, combo, passive, active, jitter, diffInfo, &metric)

			// update the diff map with the new data
			interfaceDiffLocker.Lock()
			delete(interfaceDiffMap, item.Iface)
			interfaceDiffMap[item.Iface] = diffInfo
			interfaceDiffLocker.Unlock()
		}
	}

	allstats := MakeStatsJSON(istats)
	WriteStatsJSON(allstats)
}

func logInterfaceStats(seconds uint64, interfaceID int, combo Collector, passive Collector, active Collector, jitter Collector, diffInfo *linux.NetworkStat, diffMetric *interfaceMetric) {
	// MFW-1012 - we want to show LAN interface stats in the user interface
	// but don't want them skewing the interface stats graphs so we added
	// the is_wan boolean so the UI can decide what to show
	wanFlag := getInterfaceWanFlag(diffInfo.Iface)

	columns := map[string]interface{}{
		"time_stamp":               time.Now(),
		"interface_id":             interfaceID,
		"device_name":              diffInfo.Iface,
		"is_wan":                   wanFlag,
		"latency_1":                combo.Latency1Min.Value,
		"latency_5":                combo.Latency5Min.Value,
		"latency_15":               combo.Latency15Min.Value,
		"latency_variance":         combo.LatencyVariance.StdDeviation,
		"passive_latency_1":        passive.Latency1Min.Value,
		"passive_latency_5":        passive.Latency5Min.Value,
		"passive_latency_15":       passive.Latency15Min.Value,
		"passive_latency_variance": passive.LatencyVariance.StdDeviation,
		"active_latency_1":         active.Latency1Min.Value,
		"active_latency_5":         active.Latency5Min.Value,
		"active_latency_15":        active.Latency15Min.Value,
		"active_latency_variance":  active.LatencyVariance.StdDeviation,
		"jitter_1":                 jitter.Latency1Min.Value,
		"jitter_5":                 jitter.Latency5Min.Value,
		"jitter_15":                jitter.Latency15Min.Value,
		"jitter_variance":          jitter.LatencyVariance.StdDeviation,
		"ping_timeout":             diffMetric.PingTimeout,
		"ping_timeout_rate":        diffMetric.PingTimeout / seconds,
		"rx_bytes":                 diffInfo.RxBytes,
		"rx_bytes_rate":            diffInfo.RxBytes / seconds,
		"rx_packets":               diffInfo.RxPackets,
		"rx_packets_rate":          diffInfo.RxPackets / seconds,
		"rx_errs":                  diffInfo.RxErrs,
		"rx_errs_rate":             diffInfo.RxErrs / seconds,
		"rx_drop":                  diffInfo.RxDrop,
		"rx_drop_rate":             diffInfo.RxDrop / seconds,
		"rx_fifo":                  diffInfo.RxFifo,
		"rx_fifo_rate":             diffInfo.RxFifo / seconds,
		"rx_frame":                 diffInfo.RxFrame,
		"rx_frame_rate":            diffInfo.RxFrame / seconds,
		"rx_compressed":            diffInfo.RxCompressed,
		"rx_compressed_rate":       diffInfo.RxCompressed / seconds,
		"rx_multicast":             diffInfo.RxMulticast,
		"rx_multicast_rate":        diffInfo.RxMulticast / seconds,
		"tx_bytes":                 diffInfo.TxBytes,
		"tx_bytes_rate":            diffInfo.TxBytes / seconds,
		"tx_packets":               diffInfo.TxPackets,
		"tx_packets_rate":          diffInfo.TxPackets / seconds,
		"tx_errs":                  diffInfo.TxErrs,
		"tx_errs_rate":             diffInfo.TxErrs / seconds,
		"tx_drop":                  diffInfo.TxDrop,
		"tx_drop_rate":             diffInfo.TxDrop / seconds,
		"tx_fifo":                  diffInfo.TxFifo,
		"tx_fifo_rate":             diffInfo.TxFifo / seconds,
		"tx_colls":                 diffInfo.TxColls,
		"tx_colls_rate":            diffInfo.TxColls / seconds,
		"tx_carrier":               diffInfo.TxCarrier,
		"tx_carrier_rate":          diffInfo.TxCarrier / seconds,
		"tx_compressed":            diffInfo.TxCompressed,
		"tx_compressed_rate":       diffInfo.TxCompressed / seconds,
	}

	// create a stats event and send to the logger
	event := reports.CreateEvent("interface_stats", "interface_stats", 1, columns, nil)
	reports.LogEvent(event)

	// for WAN interfaces we also send the stats to the cloud
	if wanFlag {
		reports.CloudEvent(event)
	}
}

// calculateDifference determines the difference between the two argumented values
// FIXME - need to handle integer wrap
func calculateDifference(previous uint64, current uint64) uint64 {
	diff := (current - previous)
	return diff
}

// calculateMetrics calulates the difference for other values we track for interfaces
func calculateMetrics(metric *interfaceMetric) interfaceMetric {
	var result interfaceMetric

	result.PingTimeout = metric.PingTimeout - metric.lastPingTimeout
	metric.lastPingTimeout = metric.PingTimeout
	return result
}

// checkForInterfaceChanges returns true if network interfaces have
// changed since the last time it was called, false if they have not
func checkForInterfaceChanges() bool {
	master := []byte{}

	facelist, err := net.Interfaces()
	if err != nil {
		return false
	}

	for key, item := range facelist {
		summary, err := json.Marshal(item)
		if err != nil {
			logger.Warn("Could not generate hash for item:%v value:%v\n", key, item)
			continue
		}
		master = append(master, summary...)
	}

	hash := fmt.Sprintf("%x", md5.Sum(master))

	// if nothing has changed return false
	if strings.Compare(hash, interfaceHashString) == 0 {
		return false
	}

	// changes detected so save just calculated hash for next check and return true
	interfaceHashString = hash
	return true
}

// getInterfaceIDValue is called to get the interface ID value that corresponds
// to the argumented interface name. It is used to map the system interface names
// we read from /proc/net/dev to the interface ID values we assign to each device
func getInterfaceIDValue(name string) int {
	var val *interfaceDetail

	interfaceDetailLocker.RLock()
	val = interfaceDetailMap[name]
	interfaceDetailLocker.RUnlock()

	if val != nil {
		return val.interfaceID
	}

	return -1
}

// getInterfaceWanFlag is called to get the WAN flag for the argumented interface name
func getInterfaceWanFlag(name string) bool {
	var val *interfaceDetail

	interfaceDetailLocker.RLock()
	val = interfaceDetailMap[name]
	interfaceDetailLocker.RUnlock()

	if val != nil {
		return val.wanFlag
	}

	return false
}

// loadInterfaceDetailMap creates a map of interface name to MFW interface ID values
func loadInterfaceDetailMap() {
	networkJSON, err := settings.GetCurrentSettings([]string{"network", "interfaces"})
	if networkJSON == nil || err != nil {
		logger.Warn("Unable to read network settings\n")
	}

	networkSlice, ok := networkJSON.([]interface{})
	if !ok {
		logger.Warn("Unable to locate interfaces\n")
		return
	}

	interfaceDetailLocker.Lock()
	defer interfaceDetailLocker.Unlock()

	// start with an empty map
	interfaceDetailMap = make(map[string]*interfaceDetail)

	// walk the list of interfaces and store each name and ID in the map
	for _, value := range networkSlice {
		item, ok := value.(map[string]interface{})
		if !ok {
			logger.Warn("Invalid interface in settings: %T\n", value)
			continue
		}
		if item == nil {
			logger.Warn("nil interface in interface list\n")
			continue
		}
		// Ignore hidden interfaces
		hid, found := item["hidden"]
		if found && hid.(bool) {
			continue
		}
		// We at least need the device name and interface ID
		if item["device"] == nil || item["interfaceId"] == nil {
			continue
		}

		// create a detail holder for the interface
		holder := new(interfaceDetail)
		holder.interfaceID = int(item["interfaceId"].(float64))
		holder.deviceName = item["device"].(string)

		// grab the wan flag for the interface
		wan, found := item["wan"]
		if found && wan.(bool) {
			holder.wanFlag = true
		}

		// put the interface details in the map
		interfaceDetailMap[holder.deviceName] = holder
	}
}

// refreshActivePingInfo adds details for each WAN interface that we
// use to do our active ping latency checks
func refreshActivePingInfo() {
	facelist, err := net.Interfaces()
	if err != nil {
		return
	}

	interfaceDetailLocker.Lock()
	defer interfaceDetailLocker.Unlock()

	for _, item := range facelist {
		// ignore interfaces not in our map
		if interfaceDetailMap[item.Name] == nil {
			continue
		}

		// found in the map so clear existing values
		interfaceDetailMap[item.Name].netAddress = ""
		interfaceDetailMap[item.Name].pingMode = protoIGNORE

		// ignore interfaces not flagged as WAN in our map
		if interfaceDetailMap[item.Name].wanFlag == false {
			continue
		}

		// ignore if we can't get the address list
		nets, err := item.Addrs()
		if err != nil {
			continue
		}

		// look for the first IPv4 address
		for _, addr := range nets {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil {
				continue
			}
			// we ignore anything that isn't an IPv4 address
			if ip.To4() == nil {
				continue
			}
			interfaceDetailMap[item.Name].netAddress = ip.String()
			interfaceDetailMap[item.Name].pingMode = protoICMP4
			logger.Trace("Adding IPv4 active ping interface: %v\n", ip)
			break
		}

		// if we found an IPv4 address for the interface we are finished
		if interfaceDetailMap[item.Name].pingMode != protoIGNORE {
			continue
		}

		// we didn't find an IPv4 address so try again
		for _, addr := range nets {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil {
				continue
			}
			// this time we ignore IPv4 addresses
			if ip.To4() != nil {
				continue
			}
			interfaceDetailMap[item.Name].netAddress = ip.String()
			interfaceDetailMap[item.Name].pingMode = protoICMP6
			logger.Trace("Adding IPv6 active ping interface: %v\n", ip)
			break
		}
	}
}

// We guesstimate the hop count based on the most common TTL values
// which are 32, 64, 128, and 255
// Article: Using abnormal TTL values to detect malicious IP packets
// Ryo Yamada and Shigeki Goto
// http://journals.sfu.ca/apan/index.php/apan/article/download/14/5
func logHopCount(ctid uint32, mess dispatch.NfqueueMessage, name string) {
	var hops uint8
	var ttl uint8

	// we only look for TTL in IPv4 and IPv6 packets
	if mess.IP4Layer != nil {
		ttl = mess.IP4Layer.TTL
	} else if mess.IP6Layer != nil {
		ttl = mess.IP6Layer.HopLimit
	} else {
		return
	}

	if ttl <= 32 {
		hops = (32 - ttl)
	} else if (ttl > 32) && (ttl <= 64) {
		hops = (64 - ttl)
	} else if (ttl > 64) && (ttl <= 128) {
		hops = (128 - ttl)
	} else {
		hops = (255 - ttl)
	}

	// put the hop count in the dictionary
	dict.AddSessionEntry(ctid, name, hops)

	columns := map[string]interface{}{
		"session_id": mess.Session.GetSessionID(),
	}

	modifiedColumns := make(map[string]interface{})
	modifiedColumns[name] = hops

	reports.LogEvent(reports.CreateEvent(name, "sessions", 2, columns, modifiedColumns))
}

// GetInterfaceRateDetails returns the per second rate for available interface metrics
func GetInterfaceRateDetails(facename string) map[string]uint64 {
	var retmap map[string]uint64

	interfaceDiffLocker.RLock()
	defer interfaceDiffLocker.RUnlock()

	diffInfo := interfaceDiffMap[facename]

	if diffInfo == nil {
		return nil
	}

	retmap = make(map[string]uint64)
	retmap["rx_bytes_rate"] = diffInfo.RxBytes / interfaceStatLogIntervalSec
	retmap["rx_packets_rate"] = diffInfo.RxPackets / interfaceStatLogIntervalSec
	retmap["rx_errs_rate"] = diffInfo.RxErrs / interfaceStatLogIntervalSec
	retmap["rx_drop_rate"] = diffInfo.RxDrop / interfaceStatLogIntervalSec
	retmap["rx_fifo_rate"] = diffInfo.RxFifo / interfaceStatLogIntervalSec
	retmap["rx_frame_rate"] = diffInfo.RxFrame / interfaceStatLogIntervalSec
	retmap["rx_compressed_rate"] = diffInfo.RxCompressed / interfaceStatLogIntervalSec
	retmap["rx_multicast_rate"] = diffInfo.RxMulticast / interfaceStatLogIntervalSec
	retmap["tx_bytes_rate"] = diffInfo.TxBytes / interfaceStatLogIntervalSec
	retmap["tx_packets_rate"] = diffInfo.TxPackets / interfaceStatLogIntervalSec
	retmap["tx_errs_rate"] = diffInfo.TxErrs / interfaceStatLogIntervalSec
	retmap["tx_drop_rate"] = diffInfo.TxDrop / interfaceStatLogIntervalSec
	retmap["tx_fifo_rate"] = diffInfo.TxFifo / interfaceStatLogIntervalSec
	retmap["tx_colls_rate"] = diffInfo.TxColls / interfaceStatLogIntervalSec
	retmap["tx_carrier_rate"] = diffInfo.TxCarrier / interfaceStatLogIntervalSec
	retmap["tx_compressed_rate"] = diffInfo.TxCompressed / interfaceStatLogIntervalSec
	return retmap
}
