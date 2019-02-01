package stats

import (
	"time"

	"github.com/untangle/packetd/services/logger"
)

type MovingAverage struct {
	listData []int64
	listSize int
	listSpot int
	listFull bool
}

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

func (ma *MovingAverage) AddValue(val int64) {
	ma.listData[ma.listSpot] = val
	ma.listSpot++
	if ma.listSpot == ma.listSize {
		ma.listSpot = 0
		ma.listFull = true
	}
}

func CreateMovingAverage(size int) *MovingAverage {
	return &MovingAverage{
		listSize: size,
		listSpot: 0,
		listData: make([]int64, size),
	}
}

func (ma *MovingAverage) DumpStatistics() {
	logger.Debug("Last 10 sessions ....... %v\n", time.Duration(ma.GetWindowAverage(10)))
	logger.Debug("Last 100 sessions ...... %v\n", time.Duration(ma.GetWindowAverage(100)))
	logger.Debug("Last 1000 sessions ..... %v\n", time.Duration(ma.GetWindowAverage(1000)))
	logger.Debug("Last 10000 sessions .... %v\n", time.Duration(ma.GetWindowAverage(10000)))
}
