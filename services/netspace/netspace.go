package netspace

import (
	"container/list"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/untangle/packetd/services/logger"
	"github.com/untangle/packetd/services/settings"
)

/*
	Class for managing network address blocks that are in use across all
	applications and services.
*/

const generationAttempts = 16

// NetworkSpace stores details about a network address block
type NetworkSpace struct {
	OwnerName    string
	OwnerPurpose string
	Network      net.IPNet
}

var networkRegistry *list.List
var networkMutex sync.RWMutex
var randomGenerator *rand.Rand

// Startup is called to handle service startup
func Startup() {
	networkRegistry = list.New()
	randomGenerator = rand.New(rand.NewSource(time.Now().UnixNano()))
}

// Shutdown is called to handle service shutdown
func Shutdown() {
}

// RegisterNetworkParts is called to register a network address block reservation
// @param ownerName - The name of the network block owner
// @param ownerPurpose - What the network block is being used for
// @param networkAddress - The network address
// @param networkSize - The network size
func RegisterNetworkParts(ownerName string, ownerPurpose string, networkAddress net.IP, networkSize int) {
	var netobj net.IPNet

	netobj.IP = networkAddress

	if networkAddress.To4() == nil {
		netobj.Mask = net.CIDRMask(networkSize, 128)
	} else {
		netobj.Mask = net.CIDRMask(networkSize, 32)
	}

	RegisterNetworkNet(ownerName, ownerPurpose, netobj)
}

// RegisterNetworkCIDR is called to register a network address block reservation
// @param ownerName - The name of the network block owner
// @param ownerPurpose - What the network block is being used for
// @param networkText - The network in CIDR notation
func RegisterNetworkCIDR(ownerName string, ownerPurpose string, networkText string) {
	_, netobj, err := net.ParseCIDR(networkText)
	if err != nil {
		logger.Warn("Error %v registering CIDR: %s\n", err, networkText)
		return
	}

	RegisterNetworkNet(ownerName, ownerPurpose, *netobj)
}

// RegisterNetworkNet is called to register a network address block reservation
// @param ownerName - The name of the network block owner
// @param ownerPurpose - What the network block is being used for
// @param networkInfo - The network
func RegisterNetworkNet(ownerName string, ownerPurpose string, networkInfo net.IPNet) {
	space := new(NetworkSpace)
	space.OwnerName = ownerName
	space.OwnerPurpose = ownerPurpose
	space.Network = networkInfo
	networkMutex.Lock()
	networkRegistry.PushBack(space)
	networkMutex.Unlock()
	logger.Debug("Added Netspace: %v\n", space)
}

// ClearOwnerRegistrationAll is called to clear all reservations for a specified owner
// @param ownerName - The name of the owner for which to clear network registrations
func ClearOwnerRegistrationAll(ownerName string) {
	var space *NetworkSpace

	networkMutex.Lock()

	for item := networkRegistry.Front(); item != nil; item = item.Next() {
		space = item.Value.(*NetworkSpace)
		if space.OwnerName == ownerName {
			networkRegistry.Remove(item)
			logger.Debug("Removed Netspace: %v\n", space)
		}
	}

	networkMutex.Unlock()
}

// ClearOwnerRegistrationPurpose is called to clear all reservations for a specified owner and purpose
// @param ownerName - The name of the owner for which to clear network registrations
// @param ownerPurpose - The purpose for which to clear network registrations
func ClearOwnerRegistrationPurpose(ownerName string, ownerPurpose string) {
	var space *NetworkSpace

	networkMutex.Lock()

	for item := networkRegistry.Front(); item != nil; item = item.Next() {
		space = item.Value.(*NetworkSpace)
		if space.OwnerName == ownerName && space.OwnerPurpose == ownerPurpose {
			networkRegistry.Remove(item)
			logger.Debug("Removed Netspace: %v\n", space)
		}
	}

	networkMutex.Unlock()
}

// IsNetworkAvailableParts checks to see if a a network address block is available
// @param ownerName - The name of the owner to ignore during the check
// @param networkAddress - The network block to check
// @param networkSize - The size of the network block to check
// @returns The NetworkSpace of the first conflict detected or nil if network is not registered
func IsNetworkAvailableParts(ownerName string, networkAddress net.IP, networkSize int) *NetworkSpace {
	var netobj net.IPNet

	netobj.IP = networkAddress

	if networkAddress.To4() == nil {
		netobj.Mask = net.CIDRMask(networkSize, 128)
	} else {
		netobj.Mask = net.CIDRMask(networkSize, 32)
	}

	return IsNetworkAvailableNet(ownerName, netobj)
}

// IsNetworkAvailableCIDR checks to see if a a network address block is available
// @param ownerName - The name of the owner to ignore during the check
// @param networkText - The network to check in CIDR notation
// @returns The NetworkSpace of the first conflict detected or nil if network is not registered
func IsNetworkAvailableCIDR(ownerName string, networkText string) *NetworkSpace {
	_, netobj, err := net.ParseCIDR(networkText)
	if err != nil {
		logger.Warn("Error %v checking CIDR: %s\n", err, networkText)
		return nil
	}

	return IsNetworkAvailableNet(ownerName, *netobj)
}

// IsNetworkAvailableNet checks to see if a a network address block is available
// @param ownerName - The name of the owner to ignore during the check
// @param networkText - The network to check
// @returns The NetworkSpace of the first conflict detected or nil if network is not registered
func IsNetworkAvailableNet(ownerName string, networkInfo net.IPNet) *NetworkSpace {
	var space *NetworkSpace

	networkMutex.RLock()
	defer networkMutex.RUnlock()

	for item := networkRegistry.Front(); item != nil; item = item.Next() {
		space = item.Value.(*NetworkSpace)
		if space.OwnerName != ownerName {
			if checkForConflict(&networkInfo, &space.Network) {
				logger.Debug("Found conflict: %v %v\n", networkInfo, space)
				return space
			}
		}
	}

	return nil
}

// used internally to check for intersection in two passed networks
// @param one - The first network for comparison
// @param two - The second network for comparision
// @returns true if the passed networks conflict or false if they do not
func checkForConflict(one *net.IPNet, two *net.IPNet) bool {
	return two.Contains(one.IP) || one.Contains(two.IP)
}

// GetAvailableAddressSpace is used to get an unregistered address space based on a random subnet
// IPv4 generation will pick something in 192.168.c.d, 172.16-31.c.d, or 10.b.c.d
// IPv6 generation will pick something in the unique local address (ULA) range
// @param ipVersion - The IP Version (4 or 6) to generate a space for
// @param hostID - The host ID
// @param networkSize - The size of the address space requested
// @returns - A net.IPNet address that is not conflicting with other address spaces on the appliance
func GetAvailableAddressSpace(ipVersion int, hostID int, networkSize int) *net.IPNet {
	if ipVersion != 4 && ipVersion != 6 {
		logger.Warn("Invalid ipVersion %d passed to GetAvailableAddressSpace\n", ipVersion)
		return nil
	}

	// Refresh the list of active network address space reservations so we can find
	// address space that doesn't conflict with anything currently in use.
	refreshNetworkRegistry()

	// validate the hostID
	if hostID > 255 || hostID < 0 {
		logger.Warn("Invalid hostID %d passed to GetAvailableAddressSpace\n", hostID)
		hostID = 0
	}

	// validate the networkSize
	if ipVersion == 4 && networkSize > 32 || networkSize < 24 {
		logger.Warn("Invalid IPv4 networkSize %d passed to GetAvailableAddressSpace\n", networkSize)
		networkSize = 24
	}

	if ipVersion == 6 && networkSize > 64 || networkSize < 0 {
		logger.Warn("Invalid IPv6 networkSize %d passed to GetAvailableAddressSpace\n", networkSize)
		networkSize = 64
	}

	testMap := make(map[string]bool)
	var randNet *net.IPNet

	// loop until we find an available network or reach the attempt limit
	for len(testMap) < generationAttempts {
		if ipVersion == 6 {
			randNet = getRandomLocalIP6Address(networkSize)
		} else {
			randNet = getRandomPrivateIP4Address(hostID, networkSize)
		}

		randTxt := randNet.String()

		// if we get a network we already tried don't count as an attempt
		if testMap[randTxt] {
			continue
		}

		// got a network we havent tried yet so add to test map
		testMap[randTxt] = true

		networkMutex.RLock()

		// see if the network conflicts with anything already registered
		for item := networkRegistry.Front(); item != nil; item = item.Next() {
			space := item.Value.(*NetworkSpace)
			// if we find a conflict nil randNet and break from the loop
			if checkForConflict(randNet, &space.Network) {
				randNet = nil
				break
			}
		}

		networkMutex.RUnlock()

		// if randNet is good we have an available address space to return
		if randNet != nil {
			return randNet
		}
	}

	// if we get here we could not find an available address space
	return nil
}

// used internally to generate a random IPv4 network address space
// @param hostID - The host ID
// @param networkSize - The size of the address space requested
// @returns - A random IPv4 private address space
func getRandomPrivateIP4Address(hostID int, networkSize int) *net.IPNet {
	var aval, bval, cval int

	// randomly pick the first octet as 192, 172, or 10 and assign the
	// second octet appropriately based on the first octet
	index := randomGenerator.Intn(3)

	// force requests for a block larger than /24 to use 10.x.x.x/8 space
	if networkSize < 24 {
		index = 2
	}

	switch index {
	case 0:
		// 192 must be in the 192.168 space
		aval = 192
		bval = 168
	case 1:
		// 172 must be in the 172.16 - 172.31 spaces
		aval = 172
		bval = randomGenerator.Intn(16) + 16
	case 2:
		// everything in the 10 space is valid
		aval = 10
		bval = randomGenerator.Intn(256)
	}

	// randomly generate the third octet
	cval = randomGenerator.Intn(256)

	// create a CIDR string from all of the different parts and use it to create a net.IPNet object
	text := fmt.Sprintf("%d.%d.%d.%d/%d", aval, bval, cval, hostID, networkSize)
	_, netobj, _ := net.ParseCIDR(text)

	return netobj
}

// used internally to generate a random IPv6 network address space
// @param networkSize - The size of the address space requested
// @returns - A random IPv6 unique local address space
func getRandomLocalIP6Address(networkSize int) *net.IPNet {
	var aa, bb, cc, dd, ee, ff, gg, hh int

	// use 0xFD as the first octet and randomly generate the next 7
	aa = 0xFD
	bb = randomGenerator.Intn(256)
	cc = randomGenerator.Intn(256)
	dd = randomGenerator.Intn(256)
	ee = randomGenerator.Intn(256)
	ff = randomGenerator.Intn(256)
	gg = randomGenerator.Intn(256)
	hh = randomGenerator.Intn(256)

	// create a CIDR string from all of the different parts and use it to create a net.IPNet object
	text := fmt.Sprintf("%02X%02X:%02X%02X:%02X%02X:%02X%02X::/%d", aa, bb, cc, dd, ee, ff, gg, hh, 128-networkSize)
	_, netobj, _ := net.ParseCIDR(text)

	return netobj
}

// GetFirstUsableAddressParts gets the first usable address in a network address space
// @param networkAddress - The network address space
// @param networkSize - The size of the network address space
// @returns The first usable IP address in the network address space
func GetFirstUsableAddressParts(networkAddress net.IP, networkSize int) net.IP {
	var netobj net.IPNet

	netobj.IP = networkAddress

	if networkAddress.To4() == nil {
		netobj.Mask = net.CIDRMask(networkSize, 128)
	} else {
		netobj.Mask = net.CIDRMask(networkSize, 32)
	}

	return GetFirstUsableAddressNet(netobj)
}

// GetFirstUsableAddressCIDR gets the first usable address in a network address space
// @param networkText - The network address space
// @returns The first usable IP address in the network address space
func GetFirstUsableAddressCIDR(networkText string) net.IP {
	_, netobj, err := net.ParseCIDR(networkText)
	if err != nil {
		logger.Warn("Error %v registering CIDR: %s\n", err, networkText)
		return nil
	}

	return GetFirstUsableAddressNet(*netobj)
}

// GetFirstUsableAddressNet gets the first usable address in a network address space
// @param networkInfo - The network address space
// @returns The first usable IP address in the network address space
func GetFirstUsableAddressNet(networkInfo net.IPNet) net.IP {
	for i := len(networkInfo.IP) - 1; i >= 0; i-- {
		// add one to the last byte of the network address to get the first usable
		networkInfo.IP[i]++
		// only increment the next byte if we overflowed
		if networkInfo.IP[i] != 0 {
			break
		}
	}

	return networkInfo.IP
}

// refreshNetworkRegistry clears and rebuilds the networkRegistry with
// all of the in-use networks that we know about.
func refreshNetworkRegistry() {
	// clear the network registry
	networkMutex.Lock()
	logger.Debug("Clearing %d entries from Netspace registry\n", networkRegistry.Len())
	networkRegistry.Init()
	networkMutex.Unlock()

	// get the current network setings
	networkJSON, err := settings.GetCurrentSettings([]string{"network", "interfaces"})
	if networkJSON == nil || err != nil {
		logger.Warn("Unable to read network settings\n")
	}

	// make sure we find the interfaces
	networkSlice, ok := networkJSON.([]interface{})
	if !ok {
		logger.Warn("Unable to locate interfaces\n")
		return
	}

	// walk the list of interfaces and register each network address space
	for _, value := range networkSlice {
		item, ok := value.(map[string]interface{})
		if !ok {
			logger.Warn("Invalid interface in settings: %T\n", value)
			continue
		}
		// ignore nil interfaces
		if item == nil {
			continue
		}
		// ignore hidden interfaces
		hid, found := item["hidden"]
		if found && hid.(bool) {
			continue
		}

		// only look for interfaces with a static address
		if item["configType"] != nil && item["configType"] != "ADDRESSED" {
			continue
		}
		if item["v4StaticAddress"] != nil && item["v4StaticPrefix"] != nil {
			netaddr := item["v4StaticAddress"].(string)
			netsize := int(item["v4StaticPrefix"].(float64))
			space := fmt.Sprintf("%s/%d", netaddr, netsize)
			RegisterNetworkCIDR("system", "interface", space)
		}
		if item["v6StaticAddress"] != nil && item["v6StaticPrefix"] != nil {
			netaddr := item["v6StaticAddress"].(string)
			netsize := int(item["v6StaticPrefix"].(float64))
			space := fmt.Sprintf("%s/%d", netaddr, netsize)
			RegisterNetworkCIDR("system", "interface", space)
		}
	}
}
