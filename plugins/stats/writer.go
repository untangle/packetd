package stats

import (
	"encoding/json"
	"io/ioutil"

	"github.com/untangle/golang-shared/services/logger"
)

// MetricJSON stores an individual metric for a stat
type MetricJSON struct {
	Name  string  `json:"name"`
	Value float64 `json:"value"`
}

// StatisticJSON stores an individual stat
type StatisticJSON struct {
	Name    string       `json:"name"`
	Unit    string       `json:"unit"`
	Metrics []MetricJSON `json:"metrics"`
}

// InterfaceStatsJSON stores all stats for an interface
type InterfaceStatsJSON struct {
	InterfaceID int             `json:"interfaceId"`
	Stats       []StatisticJSON `json:"stats"`
}

// ParentJSON stores all stats written to file
type ParentJSON struct {
	Version    int                  `json:"version"`
	Interfaces []InterfaceStatsJSON `json:"interfaces"`
}

// MakeStatisticJSON makes a StatisticJSON
func MakeStatisticJSON(name string, unit string, metrics []MetricJSON) StatisticJSON {
	var s StatisticJSON
	s.Name = name
	s.Unit = unit
	s.Metrics = metrics
	return s
}

// MakeInterfaceStatsJSON makes an InterfaceStatsJSON
func MakeInterfaceStatsJSON(interfaceID int, latency1 float64, latency5 float64, latency15 float64) InterfaceStatsJSON {
	var istats InterfaceStatsJSON
	istats.InterfaceID = interfaceID

	latencyMetrics := []MetricJSON{
		{
			Name:  "1_minute",
			Value: latency1,
		}, {
			Name:  "5_minute",
			Value: latency5,
		}, {
			Name:  "15_minute",
			Value: latency15,
		},
	}
	latencyStats := MakeStatisticJSON("latency", "ms", latencyMetrics)

	fakeMetrics100 := []MetricJSON{
		{
			Name:  "1_minute",
			Value: 100.0,
		}, {
			Name:  "5_minute",
			Value: 100.0,
		}, {
			Name:  "15_minute",
			Value: 100.0,
		},
	}
	fakeMetrics0 := []MetricJSON{
		{
			Name:  "1_minute",
			Value: 0.0,
		}, {
			Name:  "5_minute",
			Value: 0.0,
		}, {
			Name:  "15_minute",
			Value: 0.0,
		},
	}
	// FIXME - available bandwidth
	availableBandwidthStats := MakeStatisticJSON("available_bandwidth", "%", fakeMetrics100)
	// FIXME - packet loss
	packetLossStats := MakeStatisticJSON("packet_loss", "%", fakeMetrics0)
	// FIXME - jitter
	jitterStats := MakeStatisticJSON("jitter", "ms", fakeMetrics0)

	istats.Stats = []StatisticJSON{
		latencyStats,
		packetLossStats,
		jitterStats,
		availableBandwidthStats,
	}
	return istats
}

// MakeStatsJSON makes a ParentJSON object
func MakeStatsJSON(interfaceStats []InterfaceStatsJSON) ParentJSON {
	var p ParentJSON
	p.Version = 1
	p.Interfaces = interfaceStats
	return p
}

// WriteStatsJSON writes the json object to /tmp/stats.json
func WriteStatsJSON(p ParentJSON) {
	pjson, err := json.Marshal(p)
	if err != nil {
		logger.Warn("Failed to marshall JSON: %s\n", err.Error())
		return
	}
	err = ioutil.WriteFile("/tmp/stats.json", pjson, 0644)
	if err != nil {
		logger.Warn("Failed to write JSON: %s\n", err.Error())
		return
	}
}
