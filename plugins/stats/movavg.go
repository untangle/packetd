package stats

import (
	"time"

	"github.com/untangle/packetd/services/logger"
)

// MovingAverage is used to store an array of data for calculating a moving average
type MovingAverage struct {
	listData []int64
	listSize int
	listSpot int
	listFull bool
}

// GetTotalAverage gets the average of all available data
func (ma *MovingAverage) GetTotalAverage() int64 {
	var total int64
	var count int

	if ma.listFull {
		count = ma.listSize
	} else {
		count = ma.listSpot
	}

	if count == 0 {
		return 0
	}

	for i := 0; i < count; i++ {
		total += ma.listData[i]
	}

	avg := (total / int64(count))
	return avg
}

// GetWindowAverage gets the average of the last nnn samples of data
func (ma *MovingAverage) GetWindowAverage(size int) int64 {
	var total int64
	var index int

	if size > ma.listSize {
		return 0
	}

	if !ma.listFull && size > ma.listSpot {
		return 0
	}

	index = ma.listSpot

	for i := 0; i < size; i++ {
		index--
		if index < 0 {
			index = (ma.listSize - 1)
		}
		total += ma.listData[index]
	}

	avg := (total / int64(size))
	return avg
}

// AddValue adds a value to the moving average array, replacing the oldest value
// with the newest value once the array has been filled to maximum capcity
func (ma *MovingAverage) AddValue(val int64) {
	ma.listData[ma.listSpot] = val
	ma.listSpot++
	if ma.listSpot == ma.listSize {
		ma.listSpot = 0
		ma.listFull = true
	}
}

// IsEmpty returns true if the MovingAverage is completely empty
func (ma *MovingAverage) IsEmpty() bool {
	if ma.listFull == false && ma.listSpot == 0 {
		return true
	}
	return false
}

// CreateMovingAverage creates a MovingAverage object with the given size
func CreateMovingAverage(size int) *MovingAverage {
	return &MovingAverage{
		listSize: size,
		listSpot: 0,
		listData: make([]int64, size),
	}
}

func (ma *MovingAverage) dumpStatistics(index int) {
	logger.Debug("---------- INTERFACE %d AVERAGE LATENCY ----------\n", index)
	logger.Debug("  Last 10 sessions ....... %v\n", time.Duration(ma.GetWindowAverage(10)))
	logger.Debug("  Last 100 sessions ...... %v\n", time.Duration(ma.GetWindowAverage(100)))
	logger.Debug("  Last 1000 sessions ..... %v\n", time.Duration(ma.GetWindowAverage(1000)))
	logger.Debug("  Last 10000 sessions .... %v\n", time.Duration(ma.GetWindowAverage(10000)))
}
