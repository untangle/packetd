package restd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strconv"

	"github.com/untangle/packetd/plugins/stats"
	"github.com/untangle/packetd/services/logger"
	"github.com/untangle/packetd/services/settings"
)

type interfaceInfo struct {
	Device           string   `json:"device"`
	L3Device         string   `json:"l3device"`
	ConfigType       string   `json:"configType"`
	InterfaceID      int      `json:"interfaceId"`
	InterfaceName    string   `json:"name"`
	InterfaceType    string   `json:"type"`
	InterfaceModes	 []string `json:"ethLinkSupported"`
	InterfaceSpeed	 int	  `json:"ethSpeed"`
	InterfaceDuplex	 string	  `json:"ethDuplex"`
	InterfaceAuto	 bool     `json:"ethAutoneg"`
	Wan              bool     `json:"wan"`
	AddressSource    []string `json:"addressSource"`
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

// getInterfaceStatus is called to get
func getInterfaceStatus(getface string) ([]byte, error) {
	var resultList []*interfaceInfo
	var bridgeList map[string]string

	// load the current network settings
	settingIntfs, err := settings.GetSettingsSlice([]string{"network", "interfaces"})

	var ubusNetworkMap map[string]interface{}
	var ubusDeviceMap map[string]interface{}
	var ubusNetworkRaw []byte
	var ubusDeviceRaw []byte
	var ubusErr error

	// Now get the network details. We first try to call ubus to get the interface dump, but that
	// only works on OpenWRT so on failure we try to load the data from a known file which makes
	// x86 development easier. If that fails, we return the error from the original ubus call attempt.
	ubusNetworkRaw, ubusErr = exec.Command("/bin/ubus", "call", "network.interface", "dump").CombinedOutput()
	if ubusErr != nil {
		logger.Warn("Unable to call /bin/ubus: %v - Trying /etc/config/networks.json\n", ubusErr)
		ubusNetworkRaw, err = exec.Command("/bin/cat", "/etc/config/networks.json").CombinedOutput()
		if err != nil {
			return nil, ubusErr
		}
	}

	// convert the ubus data to a map of items
	err = json.Unmarshal([]byte(ubusNetworkRaw), &ubusNetworkMap)
	if err != nil {
		logger.Warn("Error calling json.Unmarshal(networks): %v\n", ubusNetworkRaw)
		return nil, err
	}

	// convert the ubusNetworkMap to a list of interfaces we can work with
	ubusNetworkList, ok := ubusNetworkMap["interface"].([]interface{})
	if !ok {
		return nil, errors.New("Missing interface object in ubus network.interface dump")
	}

	// Now get the device details. We first try to call ubus to get the device dump, but that
	// only works on OpenWRT so on failure we try to load the data from a known file which makes
	// x86 development easier. If that fails, we return the error from the original ubus call attempt.
	ubusDeviceRaw, ubusErr = exec.Command("/bin/ubus", "call", "network.device", "status").CombinedOutput()
	if ubusErr != nil {
		logger.Warn("Unable to call /bin/ubus: %v - Trying /etc/config/devices.json\n", ubusErr)
		ubusDeviceRaw, err = exec.Command("/bin/cat", "/etc/config/devices.json").CombinedOutput()
		if err != nil {
			return nil, ubusErr
		}
	}

	// convert the ubus data to a map of items
	err = json.Unmarshal([]byte(ubusDeviceRaw), &ubusDeviceMap)
	if err != nil {
		logger.Warn("Error calling jsonUnmarshal(devices): %v\n", ubusDeviceRaw)
		return nil, err
	}

	bridgeList = make(map[string]string)

	// look for all of the bridge devices and create a map of member to bridge mappings
	// so we can find the correct IP, DNS, and gateway info for bridged interfaces
	for device, config := range ubusDeviceMap {
		// make a map of the values for the device
		if entry, ok := config.(map[string]interface{}); ok {
			// make sure type is brige
			if entry["type"] == nil || entry["type"].(string) != "bridge" {
				continue
			}
			// look for and extract the bridge-members
			if list, ok := entry["bridge-members"].([]interface{}); ok {
				for _, item := range list {
					bridgeList[item.(string)] = device
				}
			}
		}
	}

	// walk through all of the interfaces we find in settings
	for _, value := range settingIntfs {
		item, ok := value.(map[string]interface{})
		if !ok || item == nil {
			logger.Warn("Unexpected object type: %T\n", value)
			continue
		}

		// ignore hidden interfaces
		if val, found := item["hidden"]; found {
			if val.(bool) {
				continue
			}
		}

		// ignore disabled interfaces
		if val, found := item["enabled"]; found {
			if !val.(bool) {
				continue
			}
		}

		// we must have the device, interfaceId, and configType
		if item["device"] == nil || item["interfaceId"] == nil || item["configType"] == nil {
			continue
		}

		// if the caller requested a specific device continue when no match
		if getface != "all" && getface != item["device"].(string) {
			continue
		}

		// we have the critical fields so create an interfaceInfo object and fill
		// it in with any other details we need from the interface settings
		worker := new(interfaceInfo)
		worker.Device = item["device"].(string)
		worker.InterfaceID = int(item["interfaceId"].(float64))
		worker.ConfigType = item["configType"].(string)

		if val, found := item["name"]; found {
			worker.InterfaceName = val.(string)
		}

		if val, found := item["type"]; found {
			worker.InterfaceType = val.(string)
		}

		if val, found := item["wan"]; found {
			worker.Wan = val.(bool)
		}

		attachNetworkDetails(worker, ubusNetworkList, bridgeList)
		attachDeviceDetails(worker, ubusDeviceMap)
		attachTrafficDetails(worker)

		// append the completed interfaceInfo to the results list
		resultList = append(resultList, worker)
	}

	// return the array of interfaceInfo objects as a json object
	data, err := json.Marshal(resultList)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// attachNetworkDetails gets the IP, DNS, L3Device, and other details for a target
// device and adds them to the interfaceInfo object
func attachNetworkDetails(worker *interfaceInfo, ubusNetworkList []interface{}, bridgeList map[string]string) {
	// The ubus network.interface dump returns a json object that includes multiple
	// entries for the IPv4 and IPv6 configurations using the same device name. The
	// logic here is to walk through each interface object in the ubus dump looking
	// for our target device. When found, we extract the available sections and
	// add the details to the interfaceInfo object we were passed.
	for _, value := range ubusNetworkList {
		item, ok := value.(map[string]interface{})
		if !ok {
			continue
		}

		// initialize L3Device as worker.Device in case we can't find a valid L3 device

		// we only look at interfaces that have a device value
		device := item["device"]

		//Only attach devices to matching device IDs
		if device == worker.Device {
			l3Device := item["l3_device"]

			//Attach the l3 Device
			// we cannot safely assume the first L3Device we find in the ubusnetworklist is the one we want,
			// because we may receive ubus interfaces out of order
			if l3Device != nil {
				// Only update the L3 Device if it doesn't match the device
				if worker.L3Device != l3Device.(string) {
					logger.Debug("%s is going to be attached to the L3 Device: %s\n", worker.Device, l3Device)
					worker.L3Device = l3Device.(string)
				}
			}
		}

		// Assign the L3 Device as the Device for now
		if worker.L3Device == "" {
			worker.L3Device = worker.Device
		}

		proto := item["proto"]
		if device == nil || proto == "pppoe" {
			// for tunX and pppoe configurations we want to use
			// the tunnel l3_device for our "device"
			device = item["l3_device"]
			if device == nil {
				continue
			}
		}

		// For bridged devices we look for the bridged-to device name. If there is no mapping
		// for the interface in the bridgeList then we just use the actual device name.
		search, ok := bridgeList[worker.L3Device]
		if !ok {
			search = worker.L3Device
		}

		// continue if this isn't the device we are looking for
		if search != device.(string) {
			continue
		}

		// add the address source info, if available
		if val, found := item["proto"]; found {
			worker.AddressSource = append(worker.AddressSource, val.(string))
		}

		// walk through each ipv4-address object for the interface
		if nodelist, ok := item["ipv4-address"].([]interface{}); ok {
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
		if nodelist, ok := item["ipv6-address"].([]interface{}); ok {
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
		if nodelist, ok := item["dns-server"].([]interface{}); ok {
			for _, item := range nodelist {
				worker.DNSServers = append(worker.DNSServers, item.(string))
			}
		}

		// walk through each route object for the interface
		if nodelist, ok := item["route"].([]interface{}); ok {
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
	}
}

// attachDeviceDetails gets the connected state for each interface and adds to the interfaceInfo object
func attachDeviceDetails(worker *interfaceInfo, ubusDeviceMap map[string]interface{}) {
	// The ubus network.device status returns a json object that includes details
	// for every configured device. It includes any defined bridges and the list
	// of members, but fortunately it also has a valid carrier boolean for each
	// member so we don't have to mess with parsing the bridge-members array.
	for device, item := range ubusDeviceMap {
		// see if the device matches the one we are looking for
		if device != worker.Device && device != worker.L3Device {
			continue
		}

		// make a map of the values for the interface
		if list, ok := item.(map[string]interface{}); ok {

			// look for and extract the carrier boolan
			if ptr, ok := list["carrier"]; ok {
				worker.Connected = ptr.(bool)
			} 
			// Get link supported modes.
			if list["link-supported"] != nil {
				if supported, ok := list["link-supported"].([]interface{}); ok {
					for _, item := range supported {
						worker.InterfaceModes = append(worker.InterfaceModes, item.(string))
					}
				}
			}
			// Get current speed, duplex and if autoneg is on/off, duplex is parsed from speed. E.g. "1000F"
			if ptr, ok := list["speed"]; ok {
				speedDuplex := ptr.(string)
				worker.InterfaceSpeed, _ = strconv.Atoi(speedDuplex[0:len(speedDuplex)-1])
				if speedDuplex[(len(speedDuplex)-1):] == "F" {
					worker.InterfaceDuplex = "full"
				} else {
					worker.InterfaceDuplex = "half"
				}
			}
			if ptr, ok := list["autoneg"]; ok {
				worker.InterfaceAuto = ptr.(bool)
			}
		}
	}
}

// attachTrafficDetails gets the interface traffic stats for a target
// device and adds them to the interfaceInfo object
func attachTrafficDetails(worker *interfaceInfo) {
	// get the interface stats for the target device
	trafficStats := stats.GetInterfaceRateDetails(worker.L3Device)
	if trafficStats == nil {
		trafficStats := stats.GetInterfaceRateDetails(worker.Device)
		if trafficStats == nil {
			return
		}
	}

	// store the stats data in passed interfaceInfo object
	worker.RxByteRate = trafficStats["rx_bytes_rate"]
	worker.RxPacketRate = trafficStats["rx_packets_rate"]
	worker.RxErrorRate = trafficStats["rx_errs_rate"]
	worker.RxDropRate = trafficStats["rx_drop_rate"]
	worker.RxFifoRate = trafficStats["rx_fifo_rate"]
	worker.RxFrameRate = trafficStats["rx_frame_rate"]
	worker.RxCompressedRate = trafficStats["rx_compressed_rate"]
	worker.RxMulticastRate = trafficStats["rx_multicast_rate"]
	worker.TxByteRate = trafficStats["tx_bytes_rate"]
	worker.TxPacketRate = trafficStats["tx_packets_rate"]
	worker.TxErrorRate = trafficStats["tx_errs_rate"]
	worker.TxDropRate = trafficStats["tx_drop_rate"]
	worker.TxFifoRate = trafficStats["tx_fifo_rate"]
	worker.TxCollisionRate = trafficStats["tx_colls_rate"]
	worker.TxCarrierRate = trafficStats["tx_carrier_rate"]
	worker.TxCompressedRate = trafficStats["tx_compressed_rate"]
}
