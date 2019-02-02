package stats

import (
	"sync"
	"time"

	"github.com/c9s/goprocinfo/linux"
	"github.com/untangle/packetd/services/dispatch"
	"github.com/untangle/packetd/services/logger"
)

const pluginName = "stats"
const listSize = 1

var latencyTracker [256]*MovingAverage
var interfaceMap map[string]*linux.NetworkStat
var shutdownChannel = make(chan bool)

type latencyInfo struct {
	latencyList  [listSize]time.Duration
	latencyCount int
	listLocker   sync.Mutex
	xmitTime     time.Time
}

// PluginStartup function is called to allow plugin specific initialization.
func PluginStartup() {
	logger.Info("PluginStartup(%s) has been called\n", pluginName)

	for x := 0; x < 256; x++ {
		latencyTracker[x] = CreateMovingAverage(10000)
	}

	interfaceMap = make(map[string]*linux.NetworkStat)
	go interfaceTask()
	dispatch.InsertNfqueueSubscription(pluginName, 2, PluginNfqueueHandler)
}

// PluginShutdown function called when the daemon is shutting down.
func PluginShutdown() {
	logger.Info("PluginShutdown(%s) has been called\n", pluginName)

	shutdownChannel <- true

	select {
	case <-shutdownChannel:
		logger.Info("Successful shutdown of interfaceTask\n")
	case <-time.After(10 * time.Second):
		logger.Warn("Failed to properly shutdown interfaceTask\n")
	}
}

// PluginNfqueueHandler is called to handle nfqueue packet data.
func PluginNfqueueHandler(mess dispatch.NfqueueMessage, ctid uint32, newSession bool) dispatch.NfqueueResult {
	var result dispatch.NfqueueResult
	var stats *latencyInfo

	// create and attach latencyInfo for new sessions and retrieve for existing sessions
	if newSession {
		stats = new(latencyInfo)
		mess.Session.PutAttachment("stats_holder", stats)
	} else {
		pointer := mess.Session.GetAttachment("stats_holder")
		if pointer != nil {
			stats = pointer.(*latencyInfo)
		}
	}

	if stats == nil {
		logger.Err("Missing stats_holder for session %d\n", ctid)
		result.SessionRelease = true
		return result
	}

	stats.listLocker.Lock()
	defer stats.listLocker.Unlock()

	// for C2S packets we store the current time as the transmit time
	// for S2C packets we calculate the latency as the time elapsed since transmit
	// we don't update the xmit time if already set while waiting for a server packet
	// and we clear the xmit time after each calculation so we only look at time between
	// the client sending a packet and reciving the next packet from the server
	if mess.ClientToServer {
		if !stats.xmitTime.IsZero() {
			return result
		}
		stats.xmitTime = time.Now()
	} else {
		if stats.xmitTime.IsZero() {
			return result
		}
		duration := time.Since(stats.xmitTime)
		stats.xmitTime = time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC)
		stats.latencyList[stats.latencyCount] = duration
		stats.latencyCount++

		// release the session and add to the average once we have collected a useful amount of data
		if stats.latencyCount == listSize {
			value := calculateAverageLatency(stats)
			latencyTracker[mess.Session.ServerInterfaceID].AddValue(value.Nanoseconds())
			mess.Session.DeleteAttachment("stats_holder")
			result.SessionRelease = true
			latencyTracker[mess.Session.ServerInterfaceID].DumpStatistics()
		}
	}

	return result
}

func calculateAverageLatency(holder *latencyInfo) time.Duration {
	var total int64
	var count int64

	for i := 0; i < holder.latencyCount; i++ {
		total += holder.latencyList[i].Nanoseconds()
		count++
	}

	return time.Duration(total / count)
}

func interfaceTask() {

	for {
		select {
		case <-shutdownChannel:
			shutdownChannel <- true
			return
		case <-time.After(timeUntilNextMin()):
			logger.Debug("Collecting interface statistics\n")
			collectInterfaceStats()
		}
	}
}

// timeUntilNextMin provides the exact duration until the start of the next minute
func timeUntilNextMin() time.Duration {
	t := time.Now()
	var secondsToWait = 59 - t.Second()
	var millisecondsToWait = 1000 - (t.Nanosecond() / 1000000)
	var duration = (time.Duration(secondsToWait) * time.Second) + (time.Duration(millisecondsToWait) * time.Millisecond)

	return duration
}

func collectInterfaceStats() {
	var statInfo *linux.NetworkStat
	var diffInfo linux.NetworkStat

	procData, err := linux.ReadNetworkStat("/proc/net/dev")
	if err != nil {
		logger.Err("Error reading interface statistics:%v\n", err)
		return
	}

	for i := 0; i < len(procData); i++ {
		item := procData[i]
		statInfo = interfaceMap[item.Iface]
		// if no entry for the interface use the existing values as the starting point
		if statInfo == nil {
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
			interfaceMap[item.Iface] = statInfo
			logger.Info("EMPTY: %s\n", item.Iface)
		// found the interface entry so calculate the difference since last time
		// pass previous values as pointers so they can be updated after the calculation
		} else {
			diffInfo.Iface = item.Iface
			diffInfo.RxBytes = calculateDifference(&statInfo.RxBytes, item.RxBytes)
			diffInfo.RxPackets = calculateDifference(&statInfo.RxPackets, item.RxPackets)
			diffInfo.RxErrs = calculateDifference(&statInfo.RxErrs, item.RxErrs)
			diffInfo.RxDrop = calculateDifference(&statInfo.RxDrop, item.RxDrop)
			diffInfo.RxFifo = calculateDifference(&statInfo.RxFifo, item.RxFifo)
			diffInfo.RxFrame = calculateDifference(&statInfo.RxFrame, item.RxFrame)
			diffInfo.RxCompressed = calculateDifference(&statInfo.RxCompressed, item.RxCompressed)
			diffInfo.RxMulticast = calculateDifference(&statInfo.RxMulticast, item.RxMulticast)
			diffInfo.TxBytes = calculateDifference(&statInfo.TxBytes, item.TxBytes)
			diffInfo.TxPackets = calculateDifference(&statInfo.TxPackets, item.TxPackets)
			diffInfo.TxErrs = calculateDifference(&statInfo.TxErrs, item.TxErrs)
			diffInfo.TxDrop = calculateDifference(&statInfo.TxDrop, item.TxDrop)
			diffInfo.TxFifo = calculateDifference(&statInfo.TxFifo, item.TxFifo)
			diffInfo.TxColls = calculateDifference(&statInfo.TxColls, item.TxColls)
			diffInfo.TxCarrier = calculateDifference(&statInfo.TxCarrier, item.TxCarrier)
			diffInfo.TxCompressed = calculateDifference(&statInfo.TxCompressed, item.TxCompressed)
			logger.Info("STATS: %v\n", diffInfo)
		}
	}
}

func calculateDifference(previous *uint64, current uint64) uint64 {
	// TODO - need to handle integer wrap

	diff :=	(current - *previous)
	*previous = current
	return diff
}
