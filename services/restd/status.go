package restd

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

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

	clock, err := exec.Command("date", "-R").CombinedOutput()
	if err != nil {
		logger.Warn("Error reading system clock: %s\n", err.Error())
	} else {
		stats["system_clock"] = strings.TrimRight(string(clock), "\r\n")
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
		if cpuinfo.Processors[0].ModelName == "" {
			cpuinfo.Processors[0].ModelName = getMachineType()
		}
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

// statusLicense is the RESTD /api/status/license handler
func statusLicense(c *gin.Context) {
	logger.Debug("statusLicense()\n")

	jsonO, err := getLicenseInfo()
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

// statusCommandFindAccount command result from command center find_account api call.
func statusCommandFindAccount(c *gin.Context) {
	logger.Debug("statusCommandFindAccount()\n")

	jsonO, err := getCommandFindAccount()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}

	c.JSON(http.StatusOK, jsonO)
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

	result, err := getInterfaceStatus(device)
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

// statusWifiModelist gets available wifi channel modes for a given wireless device
func statusWifiModelist(c *gin.Context) {
	device := c.Param("device")

	result, err := getWifiModelist(device)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}

	c.JSON(http.StatusOK, result)
	return
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

type wifiModeInfo struct {
	Name string `json:"name"`
	Mode string `json:"mode"`
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

// getCommandFindAccount returns result of calling command center find_account api.
func getCommandFindAccount() (map[string]interface{}, error) {
	jsonO := make(map[string]interface{})

	uid, err := settings.GetUID()
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: transport, Timeout: time.Duration(5 * time.Second)}
	req, err := http.NewRequest("GET", "https://www.untangle.com/store/open.php?action=find_account&uid=" + uid, nil)
	if err != nil {
		logger.Err("Error performing request for find_account: %v\n", err)
		return jsonO, err
	}

	resp, err := client.Do(req)
	if err != nil {
		// logger.Warn("Error calling client.Do: %s\n", err.Error())
		logger.Err("Unable to process request");
		return jsonO, err
	}
	defer resp.Body.Close()

	if err != nil {
		return jsonO, err
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logger.Err("Error reading body of find_account: %v\n", err)
		return jsonO, err
	}

	if resp.StatusCode != http.StatusOK {
		logger.Err("Error reading body of find_account: %v\n", err)
		return jsonO, err
	}

	head := bytes.Index(bodyBytes, []byte("{"))
	tail := bytes.LastIndex(bodyBytes, []byte("}"))
	if head < 0 || tail < 0 {
		return nil, errors.New("Invalid find_account api file format")
	}
	err = json.Unmarshal([]byte(bodyBytes[head:tail+1]), &jsonO)
	if err != nil {
		return nil, err
	}

	return jsonO, nil
}


// getLicenseInfo returns the license info as a json map
func getLicenseInfo() (map[string]interface{}, error) {
	file, err := os.Open("/etc/config/licenses.json")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	rawdata, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}

	head := bytes.Index(rawdata, []byte("{"))
	tail := bytes.LastIndex(rawdata, []byte("}"))
	if head < 0 || tail < 0 {
		return nil, errors.New("Invalid license file format")
	}

	jsonO := make(map[string]interface{})
	err = json.Unmarshal([]byte(rawdata[head:tail+1]), &jsonO)
	if err != nil {
		return nil, err
	}

	return jsonO, nil
}

// getBoardName returns the board name of the SOC system
func getBoardName() (string, error) {
	var file *os.File
	_, err := os.Stat("/tmp/sysinfo/untangle_board_name")
	if os.IsNotExist(err) {
		file, err = os.Open("/tmp/sysinfo/board_name")
	} else {
		file, err = os.Open("/tmp/sysinfo/untangle_board_name")
	}
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
			uint(parsedChannel),
		}

		availableFreqs = append(availableFreqs, freqMatch)
	}

	return availableFreqs, nil
}

// getWifiChannels will retrieve the wifi channels available to a given interface name using "iwinfo"
func getWifiModelist(device string) ([]wifiModeInfo, error) {
	cmdArgs := []string{device, "htmodelist"}
	cmdResult, err := exec.Command("/usr/bin/iwinfo", cmdArgs...).CombinedOutput()

	if err != nil {
		logger.Err("iwinfo failed during getWifiModelist: %v\n", err)
		return nil, err
	}

	availableModes := []wifiModeInfo{}
	availableModes = append(availableModes, wifiModeInfo{"AUTO", "AUTO"})

	modeList := strings.Fields(string(cmdResult))

	for _, mode := range modeList {
		var modeInfo = wifiModeInfo{
			string(mode),
			string(mode),
		}
		availableModes = append(availableModes, modeInfo)
	}

	return availableModes, nil
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
