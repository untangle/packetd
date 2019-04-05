package restd

import (
	"bufio"
	"net/http"
	"os"
	"strings"

	"github.com/c9s/goprocinfo/linux"
	"github.com/gin-gonic/gin"
	"github.com/untangle/packetd/services/logger"
)

// statusSystem is the RESTD /api/status/system handler
func statusSystem(c *gin.Context) {
	logger.Debug("statusSystem()\n")

	stats := make(map[string]interface{})

	loadAvg, err := linux.ReadLoadAvg("/proc/loadavg")
	if err != nil {
		logger.Warn("Error reading loadavg: %s\n", err.Error())
	} else {
		stats["loadavg"] = loadAvg
	}

	meminfo, err := linux.ReadMemInfo("/proc/meminfo")
	if err != nil {
		logger.Warn("Error reading meminfo: %s\n", err.Error())
	} else {
		stats["meminfo"] = meminfo
	}

	uptime, err := linux.ReadUptime("/proc/uptime")
	if err != nil {
		logger.Warn("Error reading uptime: %s\n", err.Error())
	} else {
		stats["uptime"] = uptime
	}

	diskstats, err := linux.ReadDiskStats("/proc/diskstats")
	if err != nil {
		logger.Warn("Error reading diskstats: %s\n", err.Error())
	} else {
		stats["diskstats"] = diskstats
	}

	rootfs, err := linux.ReadDisk("/")
	if err != nil {
		logger.Warn("Error reading disk: %s\n", err.Error())
	} else {
		stats["rootfs"] = rootfs
	}

	tmpfs, err := linux.ReadDisk("/tmp")
	if err != nil {
		logger.Warn("Error reading disk: %s\n", err.Error())
	} else {
		stats["tmpfs"] = tmpfs
	}

	c.JSON(http.StatusOK, stats)
}

// statusHardware is the RESTD /api/status/system handler
func statusHardware(c *gin.Context) {
	logger.Debug("statusHardware()\n")

	stats := make(map[string]interface{})

	cpuinfo, err := linux.ReadCPUInfo("/proc/cpuinfo")
	if err != nil {
		logger.Warn("Error reading cpuinfo: %s\n", err.Error())
	} else {
		stats["cpuinfo"] = cpuinfo
	}

	boardName, err := getBoardName()
	if err != nil {
		logger.Warn("Error reading board name: %s\n", err.Error())
	} else {
		stats["boardName"] = boardName
	}

	c.JSON(http.StatusOK, stats)
}

// statusBuild is the RESTD /api/status/build handler
func statusBuild(c *gin.Context) {
	logger.Debug("statusBuild()\n")

	jsonO, err := getBuildInfo()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}

	c.JSON(http.StatusOK, jsonO)
}

// getBuildInfo returns the build info as a json map
func getBuildInfo() (map[string]interface{}, error) {
	jsonO := make(map[string]interface{})

	file, err := os.Open("/etc/os-release")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), "=", 2)
		if len(parts) != 2 {
			continue
		}

		jsonO[strings.ToLower(parts[0])] = parts[1]
	}

	return jsonO, nil
}

// getBoardName returns the board name of the SOC system
func getBoardName() (string, error) {
	file, err := os.Open("/tmp/sysinfo/board_name")
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		return scanner.Text(), nil
	}

	return "unknown", nil
}
