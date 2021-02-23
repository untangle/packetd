package webroot

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
    "strings"
	"strconv"
	"github.com/fatih/pool"
	"github.com/untangle/packetd/services/logger"
)

type LookupResult struct {
	Ip string `json:"ip"`
	Ipint int `json:"ipint"`
	Reputation int `json:"reputation"`
	Status int `json:"status"`
	ThreatMask int `json:"threat_mask"`
	Source string `json:"source"`
}

const URI_SLASH string = "/"
const DOMAIN_PORT string = ":"
const DOMAIN_WILDCARD string = "*."
const CONN_POOL_SIZE int = 25

var connPool pool.Pool

var webrootConn = func() (net.Conn, error) { return net.Dial("tcp", "localhost:8484") }

// Startup is called when the packetd service starts
func Startup() {
	var err error
	logger.Info("Starting up the threatprevention service\n")
	// Create a socket pool to handle request to the bcdtid daemon
	connPool, err = pool.NewChannelPool(5, 30, webrootConn)
	
	if err != nil {
		logger.Info("threatprevention not able to create connection pool\n")
	}
	logger.Info("Pool connections available " + strconv.Itoa(connPool.Len()) + "\n")
}

// Shutdown is called when the packetd service stops
func Shutdown() {
	logger.Info("Shutting down the threatprevention service\n")
	connPool.Close()
}

/**
 * Brightcloud expects urls to not have wildcards or ports.
 * While we could do this only on queries, since callers are expected to look at
 * the url field in answers, they'll have a mismatch.  This allows callers to have
 * a properly normalized key for their lookups.
 * @param url String of url.
 * @return String of Brightcloud normalized url.
 */
func normalizeUrl(url string) (string) {
	var domain, path string
	var pos = strings.Index(url, URI_SLASH)
	if pos == -1 {
		domain = url
		path = ""
	} else {
		domain = strings.Split(url, URI_SLASH)[0]
		path = strings.SplitN(url, URI_SLASH, 1)[1]
	}
	
	/**
	 * While Brightcloud can handle domains with ports its very expensive, around 100 times slower.
	 */
	if strings.Contains(domain, DOMAIN_PORT) {
		domain = strings.Split(domain, DOMAIN_PORT)[0]
	}

	/**
     * If we see "*.domain.com", strip the wildcard and do lookup on remaining.
     */
	 if strings.Contains(domain, DOMAIN_WILDCARD) {
		domain = strings.Split(domain, DOMAIN_WILDCARD)[1]
	 }

	 return domain + path
}

func apiQuery(cmd string, retry bool) (string, error) {
	var err error = nil
	s, err := connPool.Get()
	fmt.Fprintf(s, "%s\r\n", cmd)
	result, err := bufio.NewReader(s).ReadString('\n')
	if err != nil {
		logger.Info("threatprevention, not able to obtain connection to bctid\n")
	}
	s.Close()

	return result, err
}

// host can be IP or FQDN.
func GetInfo(host string) (string, error) {
	addr := net.ParseIP(host)
	if addr != nil {
		return QueryIP(host)
	} else {
		return QueryUrl(host)
	}
}

// ips can be single or , seperated list of IPs
func QueryIP(ips string) (string, error) {
	cmd := "{\"ip/getinfo\" : {\"ips\": [\"" + ips + "\"]}}"
	return apiQuery(cmd, false)
}

// hosts can be single or , seperated list of FQDNs
func QueryUrl(hosts string) (string, error) {
	cmd := "{\"url/getinfo\" : {\"urls\": [\"" + hosts + "\"]}}"
	return apiQuery(cmd, false)
}

func IPLookup(ip string) (int, error) {
	var res, err = QueryIP(ip)
	if err != nil {
		return -1, err
	}
	var result []LookupResult
	json.Unmarshal([]byte(res), &result)
	return result[0].Reputation, nil
}