package netspace

import (
	"container/list"
	"net"
	"sync"

	"github.com/untangle/packetd/services/logger"
)

/*
	Class for managing network address blocks that are in use across all
	applications and services.
*/

// NetworkSpace stores details about a network address block
type NetworkSpace struct {
	OwnerName    string
	OwnerPurpose string
	Network      net.IPNet
}

var networkRegistry *list.List
var networkMutex sync.RWMutex

// Startup is called to handle service startup
func Startup() {
	logger.Debug("The netspace manager is starting\n")
	networkRegistry = list.New()

	// TODO - this is for testing and should be removed
	RegisterNetworkCIDR("test", "test", "192.168.222.0/24")
}

// Shutdown is called to handle service shutdown
func Shutdown() {
	logger.Debug("The netspace manager is finished\n")
}

// RegisterNetworkParts is called to register a network address block reservation
func RegisterNetworkParts(ownerName string, ownerPurpose string, networkAddress net.IP, networkSize int) {
	var netobj net.IPNet
	netobj.IP = networkAddress
	// TODO - need to handle IPv4 and IPv6
	netobj.Mask = net.CIDRMask(networkSize, 32)
	RegisterNetworkNet(ownerName, ownerPurpose, netobj)
}

// RegisterNetworkCIDR is called to register a network address block reservation
func RegisterNetworkCIDR(ownerName string, ownerPurpose string, networkText string) {
	_, netobj, err := net.ParseCIDR(networkText)
	if err != nil {
		logger.Warn("Error %v registering CIDR: %s\n", err, networkText)
		return
	}

	RegisterNetworkNet(ownerName, ownerPurpose, *netobj)
}

// RegisterNetworkNet is called to register a network address block reservation
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
func ClearOwnerRegistrationAll(ownerName string) {
	var worker *NetworkSpace

	networkMutex.Lock()

	for item := networkRegistry.Front(); item != nil; item = item.Next() {
		worker = item.Value.(*NetworkSpace)
		if worker.OwnerName == ownerName {
			networkRegistry.Remove(item)
			logger.Debug("Removed Netspace: %v\n", worker)
		}
	}

	networkMutex.Lock()
}

// ClearOwnerRegistrationPurpose is called to clear all reservations for a specified owner and purpose
func ClearOwnerRegistrationPurpose(ownerName string, ownerPurpose string) {
	var worker *NetworkSpace

	networkMutex.Lock()

	for item := networkRegistry.Front(); item != nil; item = item.Next() {
		worker = item.Value.(*NetworkSpace)
		if worker.OwnerName == ownerName && worker.OwnerPurpose == ownerPurpose {
			networkRegistry.Remove(item)
			logger.Debug("Removed Netspace: %v\n", worker)
		}
	}

	networkMutex.Lock()
}

// IsNetworkAvailableParts checks to see if a a network address block is available
func IsNetworkAvailableParts(ownerName string, networkAddress net.IP, networkSize int) *NetworkSpace {
	var netobj net.IPNet
	netobj.IP = networkAddress
	// TODO - need to handle IPv4 and IPv6
	netobj.Mask = net.CIDRMask(networkSize, 32)
	return IsNetworkAvailableNet(ownerName, netobj)
}

// IsNetworkAvailableCIDR checks to see if a a network address block is available
func IsNetworkAvailableCIDR(ownerName string, networkText string) *NetworkSpace {
	_, netobj, err := net.ParseCIDR(networkText)
	if err != nil {
		logger.Warn("Error %v checking CIDR: %s\n", err, networkText)
		return nil
	}

	return IsNetworkAvailableNet(ownerName, *netobj)
}

// IsNetworkAvailableNet checks to see if a a network address block is available
func IsNetworkAvailableNet(ownerName string, networkInfo net.IPNet) *NetworkSpace {
	var worker *NetworkSpace

	networkMutex.RLock()
	defer networkMutex.RUnlock()

	for item := networkRegistry.Front(); item != nil; item = item.Next() {
		worker = item.Value.(*NetworkSpace)
		if worker.OwnerName != ownerName {
			if checkForConflict(&networkInfo, &worker.Network) {
				logger.Debug("Found conflict: %v %v\n", networkInfo, worker)
				return worker
			}
		}
	}

	return nil
}

func checkForConflict(one *net.IPNet, two *net.IPNet) bool {

	/*
		TODO - THIS IS CURRENTLY BROKEN
		https://play.golang.org/p/Kur5n2hfLg

		test intersect(1.1.1.0/24,1.1.0.0/16)=false expected=true => FAIL
		test intersect(1.1.0.0/16,1.1.1.0/24)=true expected=true => good
		test intersect(1.1.1.0/24,1.1.1.0/25)=true expected=true => good
		test intersect(1.1.1.0/25,1.1.1.0/24)=true expected=true => good
		test intersect(1.1.1.0/24,1.2.0.0/16)=false expected=false => good
		test intersect(1.2.0.0/16,1.1.1.0/24)=false expected=false => good
	*/

	for i := range one.IP {
		if one.IP[i]&one.Mask[i] != two.IP[i]&two.Mask[i]&one.Mask[i] {
			return false
		}
	}
	return true
}

/*

IPMaskedAddress getAvailableAddressSpace(IPVersion version, int hostId, int networkSize);

InetAddress getFirstUsableAddress(InetAddress networkAddress, Integer networkSize);

InetAddress getFirstUsableAddress(String networkText);

public static enum IPVersion { IPv4, IPv6 };

private IPMaskedAddress getRandomLocalIp6Address(Random rand, int CIDRSpace);

private IPMaskedAddress getRandomLocalIp4Address(Random rand, int hostIdentifier, int CIDRSpace);

*/
