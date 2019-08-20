package restd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
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

// statusInterfaces is the RESTD /api/status/interfaces handler
func statusInterfaces(c *gin.Context) {
	// get the device for which status is being requested
	// string will be empty if caller wants status for all
	device := c.Param("device")
	logger.Debug("statusInterfaces(%s)\n", device)

	result, err := getInterfaceInfo(device)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}

	logger.Info("RESULT = %v\n", string(result)) // TODO - remove this

	// note here: the output type is already in JSON, setting the content-type before calling c.String will force the header
	c.Header("Content-Type", "application/json")
	c.String(http.StatusOK, string(result))
	return
}

// statusDHCP is the RESTD /api/status/dhcp handler, this will return DHCP records
func statusDHCP(c *gin.Context) {

	result, err := getDHCPInfo()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}

	c.JSON(http.StatusOK, result)
	return
}

type interfaceInfo struct {
	Device     string
	Connected  bool
	IP4Addr    []string
	IP4Gateway string
	IP6Addr    []string
	IP6Gateway string
	DNSServers []string
	ComboRate  uint
	RxRate     uint
	TxRate     uint
}

type dhcpInfo struct {
	LeaseExpiration uint
	MACAddress      string
	IP4Addr         string
	Hostname        string
	ClientID        string
}

// getInterfaceInfo returns a json object with details for the requested interface
func getInterfaceInfo(getface string) ([]byte, error) {
	var ubuslist map[string]interface{}
	var result []*interfaceInfo
	var worker *interfaceInfo
	var ubusdata []byte
	var ubuserr error
	var found bool
	var err error

	// We first try to call ubus to get the interface dump, but that only works on OpenWRT so on
	// failure we try to load the data from a known file which makes x86 development easier. If
	// that fails, we return the error from the original ubus call attempt.
	ubusdata, ubuserr = exec.Command("/bin/ubus", "call", "network.interface", "dump").CombinedOutput()
	if ubuserr != nil {
		logger.Warn("Unable to call /bin/ubus: %v - Trying /etc/config/interfaces.json\n", ubuserr)
		ubusdata, err = exec.Command("/bin/cat", "/etc/config/interfaces.json").CombinedOutput()
		if err != nil {
			return nil, ubuserr
		}
	}

	err = json.Unmarshal([]byte(ubusdata), &ubuslist)
	if err != nil {
		return nil, err
	}

	// walk through each interface object in the ubus data
	for _, raw := range ubuslist["interface"].([]interface{}) {
		ubusitem, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}

		// we don't care about the loop-back device
		if ubusitem["device"].(string) == "lo" {
			continue
		}

		// if caller requested a specific device continue when no match
		if getface != "all" && getface != ubusitem["device"].(string) {
			continue
		}

		// start with an empty worker
		worker = nil

		// The ubus network.interface dump returns a json object that includes multiple
		// entries for the IPv4 and IPv6 configuration using the same device name. The
		// logic here is to create a single interfaceInfo object for each physical device
		// and then add to it as we encouter the different sections in the json dump.
		// We start by looking for an existing object for the current device iteration.
		for _, find := range result {
			if ubusitem["device"].(string) != find.Device {
				continue
			}
			worker = find
			found = true
			break
		}

		// if existing not found create a new interfaceInfo structure for the device and copy the relevant fields
		if worker == nil {
			worker = new(interfaceInfo)
			worker.Device = ubusitem["device"].(string)
			worker.Connected = ubusitem["up"].(bool)
			found = false
		}

		// walk through each ipv4-address object for the interface
		for _, item := range ubusitem["ipv4-address"].([]interface{}) {
			ptr, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			// put the address and mask in CIDR format and add to the address array
			str := fmt.Sprintf("%s/%d", ptr["address"].(string), int(ptr["mask"].(float64)))
			worker.IP4Addr = append(worker.IP4Addr, str)
		}

		// walk through each ipv6-address object for the interface
		for _, item := range ubusitem["ipv6-address"].([]interface{}) {
			ptr, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			// put the address and mask in address/prefix format and add to the address array
			str := fmt.Sprintf("%s/%d", ptr["address"].(string), int(ptr["mask"].(float64)))
			worker.IP6Addr = append(worker.IP6Addr, str)
		}

		// walk through the dns-server list object for the interface
		for _, item := range ubusitem["dns-server"].([]interface{}) {
			worker.DNSServers = append(worker.DNSServers, item.(string))
		}

		// walk through each route object for the interface
		for _, item := range ubusitem["route"].([]interface{}) {
			ptr, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			// look for the IPv4 default gateway
			if ptr["target"].(string) == "0.0.0.0" && uint(ptr["mask"].(float64)) == 0 {
				worker.IP4Gateway = ptr["nexthop"].(string)
				continue
			}
			// look for the IPv6 default gateway
			if ptr["target"].(string) == "::" && uint(ptr["mask"].(float64)) == 0 {
				worker.IP6Gateway = ptr["nexthop"].(string)
			}
		}

		// if we created a new interfaceInfo object append to our device array
		if !found {
			result = append(result, worker)
		}
	}

	// return the array of interfaceInfo objects as a json object
	data, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// getDHCPInfo returns the DHCP info as a slice of dhcpInfos
func getDHCPInfo() ([]dhcpInfo, error) {

	returnDHCPInfo := []dhcpInfo{}

	file, err := os.Open("/tmp/dhcp.leases")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		leaseValue, parseErr := strconv.ParseUint(fields[0], 0, 32)

		if parseErr != nil {
			return nil, parseErr
		}

		var dhcpEntry = dhcpInfo{
			uint(leaseValue),
			fields[1],
			fields[2],
			fields[3],
			fields[4],
		}

		returnDHCPInfo = append(returnDHCPInfo, dhcpEntry)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return returnDHCPInfo, nil
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
