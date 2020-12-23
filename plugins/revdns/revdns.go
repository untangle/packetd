package revdns

import (
	"net"
	"sync"
	"time"

	"github.com/untangle/golang-shared/services/logger"
	"github.com/untangle/packetd/services/dict"
	"github.com/untangle/packetd/services/dispatch"
)

// ReverseHolder is used to cache a list of DNS names for an IP address
type ReverseHolder struct {
	AccessTime time.Time
	NameList   []string
	Available  bool
	WaitGroup  sync.WaitGroup
	DataMutex  sync.Mutex
}

const pluginName = "revdns"
const clientSuffix = "_client"
const serverSuffix = "_server"

//const reverseTimeout = 3600
const reverseTimeout = 120

var shutdownChannel = make(chan bool)
var reverseTable map[string]*ReverseHolder
var reverseMutex sync.RWMutex
var clientMutex sync.RWMutex
var serverMutex sync.RWMutex

// PluginStartup function is called to allow plugin specific initialization.
func PluginStartup() {
	logger.Info("PluginStartup(%s) has been called\n", pluginName)
	reverseTable = make(map[string]*ReverseHolder)
	go cleanupTask()
	dispatch.InsertNfqueueSubscription(pluginName+clientSuffix, dispatch.RevDNSPriority, PluginNfqueueClientHandler)
	dispatch.InsertNfqueueSubscription(pluginName+serverSuffix, dispatch.RevDNSPriority, PluginNfqueueServerHandler)
}

// PluginShutdown function called when the daemon is shutting down.
func PluginShutdown() {
	logger.Info("PluginShutdown(%s) has been called\n", pluginName)

	shutdownChannel <- true

	select {
	case <-shutdownChannel:
		logger.Info("Successful shutdown of cleanupTask\n")
	case <-time.After(10 * time.Second):
		logger.Warn("Failed to properly shutdown cleanupTask\n")
	}

}

// PluginNfqueueClientHandler is called to handle nfqueue packet data. We look
// at the first packet of every connection, and put the reverse DNS name
// for the client address in the session and the dictionary. We get the names
// from cache if they are available, otherwise we do the reverse lookup and
// store them in the cache.
func PluginNfqueueClientHandler(mess dispatch.NfqueueMessage, ctid uint32, newSession bool) dispatch.NfqueueResult {
	var result dispatch.NfqueueResult
	result.SessionRelease = true

	// release immediately as we only care about the first packet
	dispatch.ReleaseSession(mess.Session, pluginName+clientSuffix)

	if !newSession {
		return result
	}

	findkey := mess.MsgTuple.ClientAddress.String()

	var holder *ReverseHolder

	clientMutex.RLock()
	holder = findReverse(findkey)
	clientMutex.RUnlock()

	if holder != nil {
		logger.Debug("Loading reverse names for %s ctid:%d\n", findkey, ctid)
	} else {
		logger.Debug("Fetching reverse names for %s ctid:%d\n", findkey, ctid)
		clientMutex.Lock()
		holder = new(ReverseHolder)
		holder.WaitGroup.Add(1)
		insertReverse(findkey, holder)
		clientMutex.Unlock()

		list, err := net.LookupAddr(findkey)
		holder.DataMutex.Lock()

		if err == nil && len(list) > 0 {
			logger.Debug("Successfully fetched reverse names for %s ctid:%d\n", findkey, ctid)
			holder.NameList = list
			holder.Available = true
		} else {
			logger.Debug("Could not fetch reverse names for %s ctid:%d\n", findkey, ctid)
			holder.Available = false
		}

		holder.AccessTime = time.Now()
		holder.DataMutex.Unlock()
		holder.WaitGroup.Done()
	}

	// At this point the holder has either been retrieved or created
	if holder == nil {
		logger.Err("Constraint failed: nil reverse holder\n")
		return result
	}

	// wait until the reverse names have been retrieved
	// this will only happen when two+ sessions request names for the same address at the same time
	// the first will do the reverse lookup, and the other threads will wait here
	holder.WaitGroup.Wait()
	logger.Debug("Reverse DNS holder for %s found - ctid:%d available:%v list:%v\n", findkey, ctid, holder.Available, holder.NameList)

	// if the holder is available for this server attach the names to the session
	// and put the details in the dictionary
	if holder.Available {
		attachReverseNamesToSession("client_reverse_dns", mess.Session, holder.NameList)
	}

	return result
}

// PluginNfqueueServerHandler is called to handle nfqueue packet data. We look
// at the first packet of every connection, and put the reverse DNS name
// for the server address in the session and the dictionary. We get the names
// from cache if they are available, otherwise we do the reverse lookup and
// store them in the cache.
func PluginNfqueueServerHandler(mess dispatch.NfqueueMessage, ctid uint32, newSession bool) dispatch.NfqueueResult {
	var result dispatch.NfqueueResult
	result.SessionRelease = true

	// release immediately as we only care about the first packet
	dispatch.ReleaseSession(mess.Session, pluginName+serverSuffix)

	if !newSession {
		return result
	}

	findkey := mess.MsgTuple.ServerAddress.String()

	var holder *ReverseHolder

	serverMutex.RLock()
	holder = findReverse(findkey)
	serverMutex.RUnlock()

	if holder != nil {
		logger.Debug("Loading reverse names for %s ctid:%d\n", findkey, ctid)
	} else {
		logger.Debug("Fetching reverse names for %s ctid:%d\n", findkey, ctid)
		serverMutex.Lock()
		holder = new(ReverseHolder)
		holder.WaitGroup.Add(1)
		insertReverse(findkey, holder)
		serverMutex.Unlock()

		list, err := net.LookupAddr(findkey)
		holder.DataMutex.Lock()

		if err == nil && len(list) > 0 {
			logger.Debug("Successfully fetched reverse names for %s ctid:%d\n", findkey, ctid)
			holder.NameList = list
			holder.Available = true
		} else {
			logger.Debug("Could not fetch reverse names for %s ctid:%d\n", findkey, ctid)
			holder.Available = false
		}

		holder.AccessTime = time.Now()
		holder.DataMutex.Unlock()
		holder.WaitGroup.Done()
	}

	// At this point the holder has either been retrieved or created
	if holder == nil {
		logger.Err("Constraint failed: nil reverse holder\n")
		return result
	}

	// wait until the reverse names have been retrieved
	// this will only happen when two+ sessions request names for the same address at the same time
	// the first will do the reverse lookup, and the other threads will wait here
	holder.WaitGroup.Wait()
	logger.Debug("Reverse DNS holder for %s found - ctid:%d available:%v list:%v\n", findkey, ctid, holder.Available, holder.NameList)

	// if the holder is available for this server attach the names to the session
	// and put the details in the dictionary
	if holder.Available {
		attachReverseNamesToSession("server_reverse_dns", mess.Session, holder.NameList)
	}

	return result
}

// attachReverseNamesToSession is called to attach the reverse DNS names to a
// session entry and put them in the dictionary
func attachReverseNamesToSession(keyname string, session *dispatch.Session, list []string) {
	var builder string

	for i := 0; i < len(list); i++ {
		if i > 0 {
			builder += "|"
		}
		builder += list[i]
	}

	session.PutAttachment(keyname, builder)
	dict.AddSessionEntry(session.GetConntrackID(), keyname, builder)
}

// findReverse fetches the cached names for the argumented address.
func findReverse(finder string) *ReverseHolder {
	reverseMutex.RLock()
	entry := reverseTable[finder]
	reverseMutex.RUnlock()
	return entry
}

// insertReverse adds an address and list of names to the cache
func insertReverse(finder string, holder *ReverseHolder) {
	reverseMutex.Lock()
	if reverseTable[finder] != nil {
		delete(reverseTable, finder)
	}
	reverseTable[finder] = holder
	reverseMutex.Unlock()
}

// removeAddress removes an address from the cache
func removeReverse(finder string) {
	reverseMutex.Lock()
	delete(reverseTable, finder)
	reverseMutex.Unlock()
}

// cleanReverseTable cleans the address table by removing stale entries
func cleanReverseTable() {
	var counter int
	nowtime := time.Now()

	reverseMutex.Lock()
	defer reverseMutex.Unlock()

	for key, val := range reverseTable {
		val.DataMutex.Lock()
		if nowtime.Unix() < (val.AccessTime.Unix() + reverseTimeout) {
			logger.Trace("revdns leaving ADDR:%s LIST:%v in table\n", key, val.NameList)
			val.DataMutex.Unlock()
			continue
		}
		logger.Trace("revdns removing ADDR:%s LIST:%v from table\n", key, val.NameList)
		delete(reverseTable, key)
		val.DataMutex.Unlock()
		counter++
	}

	logger.Debug("cleanReverseTable REMOVED:%d REMAINING:%d\n", counter, len(reverseTable))
}

// periodic task to clean the address table
func cleanupTask() {
	for {
		select {
		case <-shutdownChannel:
			shutdownChannel <- true
			return
		case <-time.After(60 * time.Second):
			cleanReverseTable()
		}
	}
}
