package stats

import (
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/c9s/goprocinfo/linux"
	"github.com/untangle/packetd/services/dict"
	"github.com/untangle/packetd/services/dispatch"
	"github.com/untangle/packetd/services/logger"
	"github.com/untangle/packetd/services/reports"
	"github.com/untangle/packetd/services/settings"
)

// const values used as index for the different stats we track for each interface
// iota starts with zero so bucketCount at the end gives us the correct array size
const (
	passiveLatency int = iota
	activeLatency
	combinedLatency
	pingTimeout
	rxBytes
	rxPackets
	rxErrors
	rxDrop
	rxFifo
	rxFrame
	rxCompressed
	rxMulticast
	txBytes
	txPackets
	txErrors
	txDrop
	txFifo
	txCollision
	txCarrier
	txCompressed
	bucketCount // this identifier should always be last
)

const pluginName = "stats"
const interfaceStatLogIntervalSec = 10
const pingCheckIntervalSec = 5
const pingCheckTimeoutSec = 5

var pingCheckTargets = [...]string{"www.google.com", "8.8.8.8", "1.1.1.1"}

var statsCollector [256][bucketCount]*Collector
var statsLocker [256]sync.Mutex

var interfaceInfoMap map[string]*interfaceDetail
var interfaceInfoLocker sync.RWMutex

var interfaceMetricList [256]*interfaceMetric
var interfaceMetricLocker sync.Mutex

var interfaceStatsMap map[string]*linux.NetworkStat
var interfaceChannel = make(chan bool)
var pingChannel = make(chan bool)

var randSrc rand.Source
var randGen *rand.Rand

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

	// we use random numbers in our active ping packets to help detect valid replies
	randSrc = rand.NewSource(time.Now().UnixNano())
	randGen = rand.New(randSrc)

	for x := 0; x < 256; x++ {
		for y := 0; y < bucketCount; y++ {
			statsCollector[x][y] = CreateCollector()
			interfaceMetricList[x] = new(interfaceMetric)
		}
	}

	interfaceStatsMap = make(map[string]*linux.NetworkStat)
	interfaceInfoMap = make(map[string]*interfaceDetail)

	// FIXME - this is currently only loaded once during startup
	loadInterfaceInfoMap()

	go interfaceTask()
	go pingTask()

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

	pingChannel <- true

	select {
	case <-pingChannel:
		logger.Info("Successful shutdown of pingTask\n")
	case <-time.After(10 * time.Second):
		logger.Warn("Failed to properly shutdown pingTask\n")
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
	// log and ignore traffic to unknown interface
	if interfaceID == 0 {
		//the server interface is set in the conntrack new event
		logger.Warn("Unknown interface ID: %v\n", mess.Session.GetClientSideTuple())
		return result
	}

	logger.Debug("Logging passive latency: %d, %v, %v ms\n", interfaceID, mess.Session.GetServerSideTuple().ServerAddress, (duration.Nanoseconds() / 1000000))

	statsLocker[interfaceID].Lock()
	statsCollector[interfaceID][combinedLatency].AddDataPointLimited(float64(duration.Nanoseconds())/1000000.0, 2.0)
	statsCollector[interfaceID][passiveLatency].AddDataPointLimited(float64(duration.Nanoseconds())/1000000.0, 2.0)
	statsLocker[interfaceID].Unlock()

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
			collectInterfaceStats()
			writeLatencyStatsFile()
		}
	}
}

// collectInterfaceStats gets the stats for every interface and then
// calculates and logs the difference since the last time it was called
func collectInterfaceStats() {
	var statInfo *linux.NetworkStat

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
		interfaceID := getInterfaceIDValue(item.Iface)

		// ignore if we didn't find a valid interface ID value
		if interfaceID < 0 {
			continue
		}

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
			// found the interface entry so lock collector and calculate changes since last time
			statsLocker[interfaceID].Lock()
			statsCollector[interfaceID][rxBytes].AddDataPoint(float64(calculateDifference(statInfo.RxBytes, item.RxBytes)))
			statsCollector[interfaceID][rxPackets].AddDataPoint(float64(calculateDifference(statInfo.RxPackets, item.RxPackets)))
			statsCollector[interfaceID][rxErrors].AddDataPoint(float64(calculateDifference(statInfo.RxErrs, item.RxErrs)))
			statsCollector[interfaceID][rxDrop].AddDataPoint(float64(calculateDifference(statInfo.RxDrop, item.RxDrop)))
			statsCollector[interfaceID][rxFifo].AddDataPoint(float64(calculateDifference(statInfo.RxFifo, item.RxFifo)))
			statsCollector[interfaceID][rxFrame].AddDataPoint(float64(calculateDifference(statInfo.RxFrame, item.RxFrame)))
			statsCollector[interfaceID][rxCompressed].AddDataPoint(float64(calculateDifference(statInfo.RxCompressed, item.RxCompressed)))
			statsCollector[interfaceID][rxMulticast].AddDataPoint(float64(calculateDifference(statInfo.RxMulticast, item.RxMulticast)))
			statsCollector[interfaceID][txBytes].AddDataPoint(float64(calculateDifference(statInfo.TxBytes, item.TxBytes)))
			statsCollector[interfaceID][txPackets].AddDataPoint(float64(calculateDifference(statInfo.TxPackets, item.TxPackets)))
			statsCollector[interfaceID][txErrors].AddDataPoint(float64(calculateDifference(statInfo.TxErrs, item.TxErrs)))
			statsCollector[interfaceID][txDrop].AddDataPoint(float64(calculateDifference(statInfo.TxDrop, item.TxDrop)))
			statsCollector[interfaceID][txFifo].AddDataPoint(float64(calculateDifference(statInfo.TxFifo, item.TxFifo)))
			statsCollector[interfaceID][txCollision].AddDataPoint(float64(calculateDifference(statInfo.TxColls, item.TxColls)))
			statsCollector[interfaceID][txCarrier].AddDataPoint(float64(calculateDifference(statInfo.TxCarrier, item.TxCarrier)))
			statsCollector[interfaceID][txCompressed].AddDataPoint(float64(calculateDifference(statInfo.TxCompressed, item.TxCompressed)))

			// replace the current stats map object with the one returned from ReadNetworkStat
			interfaceStatsMap[item.Iface] = &item

			// calculate the difference for other metrics we track for each interface
			interfaceMetricLocker.Lock()
			metric := calculateMetrics(interfaceMetricList[interfaceID])
			statsCollector[interfaceID][pingTimeout].AddDataPoint(float64(metric.PingTimeout))
			interfaceMetricLocker.Unlock()

			// log the interface stats and unlock
			logInterfaceStats(interfaceID, item.Iface)
			statsLocker[interfaceID].Unlock()
		}
	}
}

func logInterfaceStats(ival int, iname string) {
	columns := map[string]interface{}{
		"time_stamp":                time.Now(),
		"interface_id":              ival,
		"device_name":               iname,
		"combined_latency_1":        statsCollector[ival][combinedLatency].Avg1Min.Value,
		"combined_latency_5":        statsCollector[ival][combinedLatency].Avg5Min.Value,
		"combined_latency_15":       statsCollector[ival][combinedLatency].Avg15Min.Value,
		"combined_latency_variance": statsCollector[ival][combinedLatency].Variance.StdDeviation,
		"passive_latency_1":         statsCollector[ival][passiveLatency].Avg1Min.Value,
		"passive_latency_5":         statsCollector[ival][passiveLatency].Avg5Min.Value,
		"passive_latency_15":        statsCollector[ival][passiveLatency].Avg15Min.Value,
		"passive_latency_variance":  statsCollector[ival][passiveLatency].Variance.StdDeviation,
		"active_latency_1":          statsCollector[ival][activeLatency].Avg1Min.Value,
		"active_latency_5":          statsCollector[ival][activeLatency].Avg5Min.Value,
		"active_latency_15":         statsCollector[ival][activeLatency].Avg15Min.Value,
		"active_latency_variance":   statsCollector[ival][activeLatency].Variance.StdDeviation,
		"ping_timeout_1":            statsCollector[ival][pingTimeout].Avg1Min.Value,
		"ping_timeout_5":            statsCollector[ival][pingTimeout].Avg5Min.Value,
		"ping_timeout_15":           statsCollector[ival][pingTimeout].Avg15Min.Value,
		"ping_timeout_variance":     statsCollector[ival][pingTimeout].Variance.StdDeviation,
		"rx_bytes_1":                statsCollector[ival][rxBytes].Avg1Min.Value,
		"rx_bytes_5":                statsCollector[ival][rxBytes].Avg5Min.Value,
		"rx_bytes_15":               statsCollector[ival][rxBytes].Avg15Min.Value,
		"rx_bytes_variance":         statsCollector[ival][rxBytes].Variance.StdDeviation,
		"rx_packets_1":              statsCollector[ival][rxPackets].Avg1Min.Value,
		"rx_packets_5":              statsCollector[ival][rxPackets].Avg5Min.Value,
		"rx_packets_15":             statsCollector[ival][rxPackets].Avg15Min.Value,
		"rx_packets_variance":       statsCollector[ival][rxPackets].Variance.StdDeviation,
		"rx_errors_1":               statsCollector[ival][rxErrors].Avg1Min.Value,
		"rx_errors_5":               statsCollector[ival][rxErrors].Avg5Min.Value,
		"rx_errors_15":              statsCollector[ival][rxErrors].Avg15Min.Value,
		"rx_errors_variance":        statsCollector[ival][rxErrors].Variance.StdDeviation,
		"rx_drop_1":                 statsCollector[ival][rxDrop].Avg1Min.Value,
		"rx_drop_5":                 statsCollector[ival][rxDrop].Avg5Min.Value,
		"rx_drop_15":                statsCollector[ival][rxDrop].Avg15Min.Value,
		"rx_drop_variance":          statsCollector[ival][rxDrop].Variance.StdDeviation,
		"rx_fifo_1":                 statsCollector[ival][rxFifo].Avg1Min.Value,
		"rx_fifo_5":                 statsCollector[ival][rxFifo].Avg5Min.Value,
		"rx_fifo_15":                statsCollector[ival][rxFifo].Avg15Min.Value,
		"rx_fifo_variance":          statsCollector[ival][rxFifo].Variance.StdDeviation,
		"rx_frame_1":                statsCollector[ival][rxFrame].Avg1Min.Value,
		"rx_frame_5":                statsCollector[ival][rxFrame].Avg5Min.Value,
		"rx_frame_15":               statsCollector[ival][rxFrame].Avg15Min.Value,
		"rx_frame_variance":         statsCollector[ival][rxFrame].Variance.StdDeviation,
		"rx_compressed_1":           statsCollector[ival][rxCompressed].Avg1Min.Value,
		"rx_compressed_5":           statsCollector[ival][rxCompressed].Avg5Min.Value,
		"rx_compressed_15":          statsCollector[ival][rxCompressed].Avg15Min.Value,
		"rx_compressed_variance":    statsCollector[ival][rxCompressed].Variance.StdDeviation,
		"rx_multicast_1":            statsCollector[ival][rxMulticast].Avg1Min.Value,
		"rx_multicast_5":            statsCollector[ival][rxMulticast].Avg5Min.Value,
		"rx_multicast_15":           statsCollector[ival][rxMulticast].Avg15Min.Value,
		"rx_multicast_variance":     statsCollector[ival][rxMulticast].Variance.StdDeviation,
		"tx_bytes_1":                statsCollector[ival][txBytes].Avg1Min.Value,
		"tx_bytes_5":                statsCollector[ival][txBytes].Avg5Min.Value,
		"tx_bytes_15":               statsCollector[ival][txBytes].Avg15Min.Value,
		"tx_bytes_variance":         statsCollector[ival][txBytes].Variance.StdDeviation,
		"tx_packets_1":              statsCollector[ival][txPackets].Avg1Min.Value,
		"tx_packets_5":              statsCollector[ival][txPackets].Avg5Min.Value,
		"tx_packets_15":             statsCollector[ival][txPackets].Avg15Min.Value,
		"tx_packets_variance":       statsCollector[ival][txPackets].Variance.StdDeviation,
		"tx_errors_1":               statsCollector[ival][txErrors].Avg1Min.Value,
		"tx_errors_5":               statsCollector[ival][txErrors].Avg5Min.Value,
		"tx_errors_15":              statsCollector[ival][txErrors].Avg15Min.Value,
		"tx_errors_variance":        statsCollector[ival][txErrors].Variance.StdDeviation,
		"tx_drop_1":                 statsCollector[ival][txDrop].Avg1Min.Value,
		"tx_drop_5":                 statsCollector[ival][txDrop].Avg5Min.Value,
		"tx_drop_15":                statsCollector[ival][txDrop].Avg15Min.Value,
		"tx_drop_variance":          statsCollector[ival][txDrop].Variance.StdDeviation,
		"tx_fifo_1":                 statsCollector[ival][txFifo].Avg1Min.Value,
		"tx_fifo_5":                 statsCollector[ival][txFifo].Avg5Min.Value,
		"tx_fifo_15":                statsCollector[ival][txFifo].Avg15Min.Value,
		"tx_fifo_variance":          statsCollector[ival][txFifo].Variance.StdDeviation,
		"tx_collision_1":            statsCollector[ival][txCollision].Avg1Min.Value,
		"tx_collision_5":            statsCollector[ival][txCollision].Avg5Min.Value,
		"tx_collision_15":           statsCollector[ival][txCollision].Avg15Min.Value,
		"tx_collision_variance":     statsCollector[ival][txCollision].Variance.StdDeviation,
		"tx_carrier_1":              statsCollector[ival][txCarrier].Avg1Min.Value,
		"tx_carrier_5":              statsCollector[ival][txCarrier].Avg5Min.Value,
		"tx_carrier_15":             statsCollector[ival][txCarrier].Avg15Min.Value,
		"tx_carrier_variance":       statsCollector[ival][txCarrier].Variance.StdDeviation,
		"tx_compressed_1":           statsCollector[ival][txCompressed].Avg1Min.Value,
		"tx_compressed_5":           statsCollector[ival][txCompressed].Avg5Min.Value,
		"tx_compressed_15":          statsCollector[ival][txCompressed].Avg15Min.Value,
		"tx_compressed_variance":    statsCollector[ival][txCompressed].Variance.StdDeviation,
	}

	reports.LogEvent(reports.CreateEvent("interface_stats", "interface_stats", 1, columns, nil))
}

// writeLatencyStatsFile writes the interface latency stats to a special JSON file
func writeLatencyStatsFile() {
	var istats []InterfaceStatsJSON

	for iface := 0; iface < 256; iface++ {
		// ignore interface if we haven't captured any activity
		if statsCollector[iface][combinedLatency].GetActivityCount() == 0 {
			continue
		}

		statsLocker[iface].Lock()
		combo := statsCollector[iface][combinedLatency].MakeCopy()
		statsLocker[iface].Unlock()

		istat := MakeInterfaceStatsJSON(iface, combo.Avg1Min.Value, combo.Avg5Min.Value, combo.Avg15Min.Value)
		istats = append(istats, istat)
	}

	allstats := MakeStatsJSON(istats)
	WriteStatsJSON(allstats)
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

// getInterfaceIDValue is called to get the interface ID value that corresponds
// to the argumented interface name. It is used to map the system interface names
// we read from /proc/net/dev to the interface ID values we assign to each device
func getInterfaceIDValue(name string) int {
	var val *interfaceDetail

	interfaceInfoLocker.RLock()
	val = interfaceInfoMap[name]
	interfaceInfoLocker.RUnlock()

	if val != nil {
		return val.interfaceID
	}

	return -1
}

// loadInterfaceInfoMap creates a map of interface name to MFW interface ID values
func loadInterfaceInfoMap() {
	networkJSON, err := settings.GetSettings([]string{"network", "interfaces"})
	if networkJSON == nil || err != nil {
		logger.Warn("Unable to read network settings\n")
	}

	networkSlice, ok := networkJSON.([]interface{})
	if !ok {
		logger.Warn("Unable to locate interfaces")
		return
	}

	interfaceInfoLocker.Lock()
	defer interfaceInfoLocker.Unlock()

	// start with an empty map
	interfaceInfoMap = make(map[string]*interfaceDetail)

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
		interfaceInfoMap[holder.deviceName] = holder
	}
}

// refreshActivePingInfo adds details for each WAN interface that we
// use to do our active ping latency checks
func refreshActivePingInfo() {
	facelist, err := net.Interfaces()
	if err != nil {
		return
	}

	interfaceInfoLocker.Lock()
	defer interfaceInfoLocker.Unlock()

	for _, item := range facelist {
		// ignore interfaces not in our map
		if interfaceInfoMap[item.Name] == nil {
			continue
		}

		// found in the map so clear existing values
		interfaceInfoMap[item.Name].netAddress = ""
		interfaceInfoMap[item.Name].pingMode = protoIGNORE

		// ignore interfaces not flagged as WAN in our map
		if interfaceInfoMap[item.Name].wanFlag == false {
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
			interfaceInfoMap[item.Name].netAddress = ip.String()
			interfaceInfoMap[item.Name].pingMode = protoICMP4
			logger.Trace("Adding IPv4 active ping interface: %v\n", ip)
			break
		}

		// if we found an IPv4 address for the interface we are finished
		if interfaceInfoMap[item.Name].pingMode != protoIGNORE {
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
			interfaceInfoMap[item.Name].netAddress = ip.String()
			interfaceInfoMap[item.Name].pingMode = protoICMP6
			logger.Trace("Adding IPv6 active ping interface: %v\n", ip)
			break
		}
	}
}

func pingTask() {

	for {
		select {
		case <-pingChannel:
			pingChannel <- true
			return
		case <-time.After(time.Second * time.Duration(pingCheckIntervalSec)):
			refreshActivePingInfo()
			interfaceInfoLocker.RLock()
			for _, value := range interfaceInfoMap {
				if value.pingMode == protoIGNORE {
					continue
				}
				for x := 0; x < len(pingCheckTargets); x++ {
					collectPingSample(value, pingCheckTargets[x])
				}
			}
			interfaceInfoLocker.RUnlock()
		}
	}
}

func collectPingSample(detail *interfaceDetail, target string) {
	logger.Debug("Pinging %s with interfaceDetail[%v]\n", target, *detail)

	duration, err := pingNetworkAddress(detail.pingMode, detail.netAddress, target)

	if err != nil {
		if strings.Contains(err.Error(), "i/o timeout") {
			// if no ping response we count as a timeout
			interfaceMetricLocker.Lock()
			interfaceMetricList[detail.interfaceID].PingTimeout++
			interfaceMetricLocker.Unlock()
		} else {
			// otherwise log the error
			logger.Warn("Error returned from pingIPv4Address: %v\n", err)
		}
		return
	}

	logger.Debug("Logging active latency: %d, %v, %v ms\n", detail.interfaceID, detail.netAddress, (duration.Nanoseconds() / 1000000))

	statsLocker[detail.interfaceID].Lock()
	statsCollector[detail.interfaceID][combinedLatency].AddDataPoint(float64(duration.Nanoseconds()) / 1000000.0)
	statsCollector[detail.interfaceID][activeLatency].AddDataPoint(float64(duration.Nanoseconds()) / 1000000.0)
	statsLocker[detail.interfaceID].Unlock()
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
