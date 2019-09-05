package restd

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/c9s/goprocinfo/linux"
	"github.com/gin-gonic/gin"
	"github.com/untangle/packetd/plugins/stats"
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
		stats["cpuinfo"] = getMachineType()
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
		return
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

	// note here: the output type is already in JSON, setting the content-type before calling c.String will force the header
	c.Header("Content-Type", "application/json")
	c.String(http.StatusOK, string(result))
	return
}

// statusArp is the RESTD /api/status/arp handler, this will return the arp table
func statusArp(c *gin.Context) {
	device := c.Param("device")
	cmdArgs := []string{"neigh"}

	if len(device) > 0 {
		cmdArgs = []string{"neigh", "show", "dev", device}
	}

	result, err := runIPCommand(cmdArgs)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}

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

// statusRoute is the RESTD /api/status/route handler, this will return route information
func statusRoute(c *gin.Context) {
	table := c.Param("table")
	query := c.Request.URL.Query()

	cmdArgs := []string{"route"}

	if len(table) > 0 {
		cmdArgs = []string{"route", "show", "table", table}
	}

	//if the ip protocol is passed in, prepend it
	if query["family"] != nil && len(query["family"][0]) > 0 {
		cmdArgs = append([]string{"-" + query["family"][0]}, cmdArgs...)
	}

	result, err := runIPCommand(cmdArgs)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}

	// note here: the output type is already in JSON, setting the content-type before calling c.String will force the header
	c.Header("Content-Type", "application/json")
	c.String(http.StatusOK, string(result))
	return
}

// statusRules is the RESTD /api/status/rules handler, this will return ip rule information
func statusRules(c *gin.Context) {
	query := c.Request.URL.Query()
	cmdArgs := []string{"rule", "ls"}

	//if the ip protocol is passed in, prepend it
	if query["family"] != nil && len(query["family"][0]) > 0 {
		cmdArgs = append([]string{"-" + query["family"][0]}, cmdArgs...)
	}

	result, err := runIPCommand(cmdArgs)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}

	// note here: the output type is already in JSON, setting the content-type before calling c.String will force the header
	c.Header("Content-Type", "application/json")
	c.String(http.StatusOK, string(result))
	return
}

// statusRouteRules gets the route rules to return as a string content type
func statusRouteRules(c *gin.Context) {

	result, err := getRouteRules()

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.String(http.StatusOK, result)
	return
}

// statusRouteTables returns routing table names to pass into the statusRoute api
func statusRouteTables(c *gin.Context) {
	rtTables := []string{"main", "balance", "default", "local", "220"}

	//read through rt_tables and append
	result, err := exec.Command("awk", "/wan/ {print $2}", "/etc/iproute2/rt_tables").CombinedOutput()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	//append awk results to rtTables
	for _, s := range strings.Fields(string(result)) {
		rtTables = append(rtTables, s)
	}

	c.JSON(http.StatusOK, rtTables)
	return
}

// statusWwan is the RESTD /api/status/wwan handler, this will return wwan device info
func statusWwan(c *gin.Context) {
	device := c.Param("device")

	result, err := exec.Command("/usr/bin/wwan_status.sh", device).CombinedOutput()

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}

	c.Header("Content-Type", "application/json")
	c.String(http.StatusOK, string(result))
	return
}

// statusWifiChannels gets available wifi channels for a given wireless device
func statusWifiChannels(c *gin.Context) {
	device := c.Param("device")

	result, err := getWifiChannels(device)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}

	c.JSON(http.StatusOK, result)
	return
}

type interfaceInfo struct {
	Device           string   `json:"device"`
	Connected        bool     `json:"connected"`
	IP4Addr          []string `json:"ip4Addr"`
	IP4Gateway       string   `json:"ip4Gateway"`
	IP6Addr          []string `json:"ip6Addr"`
	IP6Gateway       string   `json:"ip6Gateway"`
	DNSServers       []string `json:"dnsServers"`
	RxByteRate       uint64   `json:"rxByteRate"`
	RxPacketRate     uint64   `json:"rxPacketRate"`
	RxErrorRate      uint64   `json:"rxErrorRate"`
	RxDropRate       uint64   `json:"rxDropRate"`
	RxFifoRate       uint64   `json:"rxFifoRate"`
	RxFrameRate      uint64   `json:"rxFrameRate"`
	RxCompressedRate uint64   `json:"rxCompressedRate"`
	RxMulticastRate  uint64   `json:"rxMulticastRate"`
	TxByteRate       uint64   `json:"txByteRate"`
	TxPacketRate     uint64   `json:"txPacketRate"`
	TxErrorRate      uint64   `json:"txErrorRate"`
	TxDropRate       uint64   `json:"txDropRate"`
	TxFifoRate       uint64   `json:"txFifoRate"`
	TxCollisionRate  uint64   `json:"txCollisionRate"`
	TxCarrierRate    uint64   `json:"txCarrierRate"`
	TxCompressedRate uint64   `json:"txCompressedRate"`
}

type dhcpInfo struct {
	LeaseExpiration uint   `json:"leaseExpiration"`
	MACAddress      string `json:"macAddress"`
	IPAddr          string `json:"ipAddr"`
	Hostname        string `json:"hostName"`
	ClientID        string `json:"clientId"`
}
type wifiChannelInfo struct {
	Frequency string `json:"frequency"`
	Channel   uint   `json:"channel"`
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

	mainlist, ok := ubuslist["interface"].([]interface{})
	if !ok {
		return nil, errors.New("Missing interface object in ubus network.interface dump")
	}

	// walk through each interface object in the ubus data
	for _, raw := range mainlist {
		ubusitem, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}

		// ignore if there is no device or up entry
		if ubusitem["device"] == nil || ubusitem["up"] == nil {
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
		if nodelist, ok := ubusitem["ipv4-address"].([]interface{}); ok {
			for _, item := range nodelist {
				if ptr, ok := item.(map[string]interface{}); ok {
					// put the address and mask in CIDR format and add to the address array
					if ptr["address"] != nil && ptr["mask"] != nil {
						str := fmt.Sprintf("%s/%d", ptr["address"].(string), int(ptr["mask"].(float64)))
						worker.IP4Addr = append(worker.IP4Addr, str)
					}
				}
			}
		}

		// walk through each ipv6-address object for the interface
		if nodelist, ok := ubusitem["ipv6-address"].([]interface{}); ok {
			for _, item := range nodelist {
				if ptr, ok := item.(map[string]interface{}); ok {
					// put the address and mask in address/prefix format and add to the address array
					if ptr["address"] != nil && ptr["mask"] != nil {
						str := fmt.Sprintf("%s/%d", ptr["address"].(string), int(ptr["mask"].(float64)))
						worker.IP6Addr = append(worker.IP6Addr, str)
					}
				}
			}
		}

		// walk through the dns-server list object for the interface
		if nodelist, ok := ubusitem["dns-server"].([]interface{}); ok {
			for _, item := range nodelist {
				worker.DNSServers = append(worker.DNSServers, item.(string))
			}
		}

		// walk through each route object for the interface
		if nodelist, ok := ubusitem["route"].([]interface{}); ok {
			for _, item := range nodelist {
				if ptr, ok := item.(map[string]interface{}); ok {
					if ptr["target"] != nil && ptr["mask"] != nil && ptr["nexthop"] != nil {
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
				}
			}
		}

		// if we created a new interfaceInfo object get the interface rate details and append to our device array
		if !found {
			facemap := stats.GetInterfaceRateDetails("wan")
			if facemap != nil {
				worker.RxByteRate = facemap["rx_bytes_rate"]
				worker.RxPacketRate = facemap["rx_packets_rate"]
				worker.RxErrorRate = facemap["rx_errs_rate"]
				worker.RxDropRate = facemap["rx_drop_rate"]
				worker.RxFifoRate = facemap["rx_fifo_rate"]
				worker.RxFrameRate = facemap["rx_frame_rate"]
				worker.RxCompressedRate = facemap["rx_compressed_rate"]
				worker.RxMulticastRate = facemap["rx_multicast_rate"]
				worker.TxByteRate = facemap["tx_bytes_rate"]
				worker.TxPacketRate = facemap["tx_packets_rate"]
				worker.TxErrorRate = facemap["tx_errs_rate"]
				worker.TxDropRate = facemap["tx_drop_rate"]
				worker.TxFifoRate = facemap["tx_fifo_rate"]
				worker.TxCollisionRate = facemap["tx_colls_rate"]
				worker.TxCarrierRate = facemap["tx_carrier_rate"]
				worker.TxCompressedRate = facemap["tx_compressed_rate"]
			}
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

// getMachineType returns the machine type and is called when /proc/cpuinfo doesn't list Hardware
func getMachineType() string {
	result, err := exec.Command("uname", "-m").CombinedOutput()

	if err != nil {
		return "unknown"
	}

	return string(result)
}

// getRouteRules will retrieve route rules using the NFT command
func getRouteRules() (string, error) {

	cmdArgs := []string{"list", "chain", "inet", "wan-routing", "user-wan-rules"}

	result, err := runNFTCommand(cmdArgs)

	if err != nil {
		return "", err
	}

	return string(result), nil
}

// getWifiChannels will retrieve the wifi channels available to a given interface name using "iwinfo"
func getWifiChannels(device string) ([]wifiChannelInfo, error) {
	cmdArgs := []string{device, "freqlist"}

	cmdResult, err := exec.Command("/usr/bin/iwinfo", cmdArgs...).CombinedOutput()

	if err != nil {
		logger.Err("iwinfo failed during getWifiChannels: %v\n", err)
		return nil, err
	}

	availableFreqs := []wifiChannelInfo{}

	// regex should match for channel frequency and channel #, split up by groupings
	channelRegex := regexp.MustCompile(`(\d*\.\d*\s[a-zA-Z]*)\s\(Channel\s(\d*)\)`)

	groupMatches := channelRegex.FindAllSubmatch(cmdResult, -1)

	for _, channelMatch := range groupMatches {
		var parsedChannel, err = strconv.ParseUint(string(channelMatch[2]), 10, 32)

		if err != nil {
			logger.Err("unable to parse channel %s : %v\n", channelMatch[2], err)
		}
		var freqMatch = wifiChannelInfo{
			string(channelMatch[1]),
			//string(channelMatch[2]),
			uint(parsedChannel),
		}

		availableFreqs = append(availableFreqs, freqMatch)
	}

	return availableFreqs, nil
}

// runIPCommand is used to run various commands using iproute2, the results from the output are byte arrays which represent json strings
func runIPCommand(cmdArgs []string) ([]byte, error) {

	// the -json flag should be prepended to the argument list
	cmdArgs = append([]string{"-json"}, cmdArgs...)

	result, err := exec.Command("ip", cmdArgs...).CombinedOutput()

	if err != nil {
		return nil, err
	}

	return result, nil
}

// runNFTCommand is used to run various commands using nft, the result is a byte array of string content (until the -json flag is available in NFT 0.9)
func runNFTCommand(cmdArgs []string) ([]byte, error) {

	//the -json flag is prepended to the arg list (uncomment when NFT is updated to 0.9)
	// cmdArgs = append([]string{"--json"}, cmdArgs...)

	result, err := exec.Command("nft", cmdArgs...).CombinedOutput()

	if err != nil {
		return nil, err
	}

	return result, nil
}
