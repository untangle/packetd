package stats

import (
	"fmt"
	"math"
	"sync/atomic"
	"time"

	"github.com/untangle/packetd/services/logger"
)

// RunningVariance tallies an running variance
type RunningVariance struct {
	Alpha        float64 // 0.0 -> 1.0
	Mean         float64
	Variance     float64
	StdDeviation float64
}

// ExponentialAverage tallies an running exponential average
type ExponentialAverage struct {
	TimeframeMilliSeconds  float64
	Value                  float64
	LastDatapointTimestamp time.Time
	CreationTime           time.Time
}

// Collector collects all the stats for a given interface
type Collector struct {
	Avg1Min       ExponentialAverage
	Avg5Min       ExponentialAverage
	Avg15Min      ExponentialAverage
	Variance      RunningVariance
	activityCount uint64
}

func (rv *RunningVariance) String() string {
	return fmt.Sprintf("%.1fms", rv.StdDeviation)
}

func (ea *ExponentialAverage) String() string {
	return fmt.Sprintf("%.1fms", ea.Value)
}

// MakeCopy makes a copy of the collector
func (c *Collector) MakeCopy() Collector {
	newc := *c
	return newc
}

// GetActivityCount safely returns the activity count when the Mutex is not locked
func (c *Collector) GetActivityCount() uint64 {
	return atomic.LoadUint64(&c.activityCount)
}

// AddDataPointLimited adds a new datapoint to a collector
// if it falls within the std deviation limit
func (c *Collector) AddDataPointLimited(value float64, deviationLimit float64) {
	atomic.AddUint64(&c.activityCount, 1)
	c.Variance.AdjustVariance(value)

	diff := math.Abs(c.Avg1Min.Value - value)
	if diff > (deviationLimit * c.Variance.StdDeviation) {
		logger.Debug("Ignoring data value: %f (diff: %f) (var: %f)\n", value, diff, c.Variance.StdDeviation)
	} else {
		c.Avg1Min.AdjustExpAvg(value)
		c.Avg5Min.AdjustExpAvg(value)
		c.Avg15Min.AdjustExpAvg(value)
		logger.Debug("Adding new datapoint: %f 1m: %s 5m: %s 15m: %s var: %s\n", value,
			c.Avg1Min.String(), c.Avg5Min.String(), c.Avg15Min.String(), c.Variance.String())
	}
}

// AddDataPoint adds a new datapoint to a collector
// if it falls within the std deviation limit
func (c *Collector) AddDataPoint(value float64) {
	atomic.AddUint64(&c.activityCount, 1)
	c.Avg1Min.AdjustExpAvg(value)
	c.Avg5Min.AdjustExpAvg(value)
	c.Avg15Min.AdjustExpAvg(value)
	c.Variance.AdjustVariance(value)
	logger.Debug("Adding new datapoint: %f 1m: %s 5m: %s 15m: %s var: %s\n", value,
		c.Avg1Min.String(), c.Avg5Min.String(), c.Avg15Min.String(), c.Variance.String())
}

// AdjustExpAvg adjust the exponential running average with the new datapoint
func (ea *ExponentialAverage) AdjustExpAvg(value float64) {
	var elapsedMilliSec float64
	now := time.Now()
	timeframe := ea.TimeframeMilliSeconds
	// if this is newly created, used a smaller timeframe
	if now.Sub(ea.CreationTime) < time.Duration(ea.TimeframeMilliSeconds)*time.Millisecond {
		timeframe = float64(now.Sub(ea.CreationTime) / time.Millisecond)
	}
	elapsed := now.Sub(ea.LastDatapointTimestamp)
	elapsedMilliSec = float64(int64(elapsed) / 1000000)

	alpha := 1.0 - math.Exp(-elapsedMilliSec/timeframe)
	ea.Value = alpha*value + (1.0-alpha)*ea.Value
	ea.LastDatapointTimestamp = now
}

// AdjustVariance adjust the variance with a new datapoint
// Adjust the variance with a new datapoint
// http://people.ds.cam.ac.uk/fanf2/hermes/doc/antiforgery/stats.pdf
func (rv *RunningVariance) AdjustVariance(value float64) {
	if rv.Mean == 0 {
		rv.Mean = value
		rv.Variance = (value * value) * 2
	}
	diff := value - rv.Mean
	incremental := rv.Alpha * diff
	rv.Mean = rv.Mean + incremental
	rv.Variance = (1.0 - rv.Alpha) * (rv.Variance + (diff * incremental))
	rv.StdDeviation = math.Sqrt(rv.Variance)
}

// CreateCollector creates a new collector
func CreateCollector() *Collector {
	c := new(Collector)

	now := time.Now()
	c.Avg1Min = ExponentialAverage{
		TimeframeMilliSeconds:  60 * 1000.0,
		LastDatapointTimestamp: now,
		CreationTime:           now,
	}
	c.Avg5Min = ExponentialAverage{
		TimeframeMilliSeconds:  5 * 60 * 1000.0,
		LastDatapointTimestamp: now,
		CreationTime:           now,
	}
	c.Avg5Min = ExponentialAverage{
		TimeframeMilliSeconds:  15 * 60 * 1000.0,
		LastDatapointTimestamp: now,
		CreationTime:           now,
	}
	c.Variance = RunningVariance{
		Alpha:    .01,
		Mean:     0.0,
		Variance: 0.0,
	}

	return c
}
