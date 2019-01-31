package stats

import (
	"sync"
	"time"

	"github.com/untangle/packetd/services/dispatch"
	"github.com/untangle/packetd/services/logger"
)

const pluginName = "stats"
const listSize = 12

type statsHolder struct {
	latencyList  [listSize]time.Duration
	latencyCount int
	listLocker   sync.Mutex
	xmitTime     time.Time
}

// PluginStartup function is called to allow plugin specific initialization.
func PluginStartup() {
	logger.Info("PluginStartup(%s) has been called\n", pluginName)
	dispatch.InsertNfqueueSubscription(pluginName, 2, PluginNfqueueHandler)
}

// PluginShutdown function called when the daemon is shutting down.
func PluginShutdown() {
	logger.Info("PluginShutdown(%s) has been called\n", pluginName)
}

// PluginNfqueueHandler is called to handle nfqueue packet data.
func PluginNfqueueHandler(mess dispatch.NfqueueMessage, ctid uint32, newSession bool) dispatch.NfqueueResult {
	var result dispatch.NfqueueResult
	var stats *statsHolder

	// create and attach statsHolder for new sessions and retrieve for existing sessions
	if newSession {
		stats = new(statsHolder)
		mess.Session.PutAttachment("stats_holder", stats)
	} else {
		stats = mess.Session.GetAttachment("stats_holder").(*statsHolder)
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
		logger.Trace("Session latency:%v | Average latency:%v\n", duration, calculateAverageLatency(stats))

		// release the session once we have collected a useful amount of data
		if stats.latencyCount == listSize {
			mess.Session.DeleteAttachment("stats_holder")
			result.SessionRelease = true
		}
	}

	return result
}

func calculateAverageLatency(holder *statsHolder) time.Duration {
	var total int64
	var count int64

	for i := 0; i < holder.latencyCount; i++ {
		total += holder.latencyList[i].Nanoseconds()
		count++
	}

	return time.Duration(total / count)
}
