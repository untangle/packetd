package restd

import (
	"bufio"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/c9s/goprocinfo/linux"
	"github.com/gin-gonic/gin"
	"github.com/untangle/packetd/services/logger"
	"github.com/untangle/packetd/services/settings"
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

// statusUID returns the UID of the system
func statusUID(c *gin.Context) {
	logger.Debug("statusUID()\n")

	uid, err := settings.GetUID()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}

	c.String(http.StatusOK, uid)
}

// statusWANTest runs the WAN performance test and returns the result
func statusWANTest(c *gin.Context) {
	logger.Debug("statusWANTest()\n")
	device := c.Param("device")

	if device == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "device not found"})
		return
	}

	output, err := exec.Command("/usr/bin/speedtest.sh", device).CombinedOutput()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
	}

	// note here: the output type is already in JSON, setting the content-type before calling c.String will force the header
	c.Header("Content-Type", "application/json")
	c.String(http.StatusOK, string(output))
	return
}

// statusUpgradeAvailable checks to see if an upgrade is available
func statusUpgradeAvailable(c *gin.Context) {
	logger.Debug("statusUpgradeAvailable()\n")

	cmd := exec.Command("/usr/bin/upgrade.sh", "-s")
	if err := cmd.Start(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
	}
	if err := cmd.Wait(); err != nil {
		if _, ok := err.(*exec.ExitError); ok {
			// child exited with non-zero
			c.JSON(http.StatusOK, gin.H{"available": false})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		}
		return
	}
	output, _ := cmd.CombinedOutput()
	r, _ := regexp.Compile("Newest\\s+Version:\\s+(\\w+)")
	newVersion := r.FindString(string(output))

	c.JSON(http.StatusOK, gin.H{"available": true, "version": newVersion})
	return
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

		jsonO[strings.ToLower(parts[0])] = strings.Trim(parts[1], "\"")
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
