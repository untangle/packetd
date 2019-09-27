// Package classify classifies sessions as certain applications
// each packet gets sent to a classd daemon (the categorization engine)
// the classd daemon returns the classification information and classify
// attaches the information to the session.
package classify

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/untangle/packetd/services/logger"
	"github.com/untangle/packetd/services/overseer"
	"github.com/untangle/packetd/services/settings"
)

const cloudUploadInterval = 60 * time.Minute
const cloudTableLimit = 100

type cloudReport struct {
	Protocol    uint8  `json:"protocol"`
	Application string `json:"application_control_application"`
	Protochain  string `json:"application_control_protochain"`
	Detail      string `json:"application_control_detail"`
	ServerAddr  string `json:"s_server_addr"`
	ServerPort  uint16 `json:"s_server_port"`
	Count       int    `json:"count"`
}

var cloudTable map[string]*cloudReport
var cloudMutex sync.Mutex

// pluginCloudManager is a goroutine to handle sending traffic reports to the cloud
func pluginCloudManager(control chan bool) {
	logger.Info("The pluginCloudManager is starting\n")
	cloudTable = make(map[string]*cloudReport)
	control <- true

	for {
		select {
		case message := <-cloudChannel:
			if message == systemShutdown {
				logger.Info("The pluginCloudManager is finished\n")
				control <- true
				return
			}
		case <-time.After(cloudUploadInterval):
			total := generateCloudReport()
			logger.Info("Sent %d classification updates to the cloud\n", total)
		}
	}
}

// storeCloudReport creates a new or updates an existing cloud report
func storeCloudReport(item *cloudReport) {
	cloudMutex.Lock()
	defer cloudMutex.Unlock()

	// the map index is created from serveraddr:serverport
	index := fmt.Sprintf("%s:%d", item.ServerAddr, item.ServerPort)

	// if we find existing entry increment counter and return
	if cloudTable[index] != nil {
		found := cloudTable[index]
		found.Count++
		return
	}

	// existing entry doesn't exist so check for table size limit
	if len(cloudTable) >= cloudTableLimit {
		overseer.AddCounter("classify_cloud_report_discard", 1)
		return
	}

	item.Count = 1
	cloudTable[index] = item
	overseer.AddCounter("classify_cloud_report_capture", 1)
}

// generateCloudReport generates json from stored reports and submits to the cloud
func generateCloudReport() int {
	var report strings.Builder
	var item *cloudReport
	var counter int
	var idx string

	// add the json header
	report.WriteString("{\n")
	report.WriteString("\"ReportName\" : \"routing data\",\n")
	report.WriteString("\"Data\" : [")

	cloudMutex.Lock()
	defer cloudMutex.Unlock()

	for idx, item = range cloudTable {
		// start by removing the entry from the table
		delete(cloudTable, idx)

		// convert the entry to json
		raw, err := json.Marshal(item)
		if err != nil {
			logger.Warn("Error %v calling json.Marshal(%v)\n", err, item)
			continue
		}

		// First time through we write a newline, on subsequent iterations we add the comma
		// for the previous line. The order here prevents a comma on the final line of data.
		if counter == 0 {
			report.WriteString("\n")
		} else {
			report.WriteString(",\n")
		}

		// now we write the item json and increment the counter
		report.WriteString(string(raw))
		counter++
	}

	// add the json footer
	report.WriteString("\n]\n}\n")

	// transmit the report to the cloud
	transmitCloudReport(report.String())
	return counter
}

// transmitCloudReport transmits the passed report to the cloud
func transmitCloudReport(message string) {
	var uid string
	var err error

	uid, err = settings.GetUID()
	if err != nil {
		logger.Warn("Unable to read UID: %s\n", err.Error())
		return
	}

	// FIXME - We disable cert checking on our http.Client for now
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: transport, Timeout: time.Duration(5 * time.Second)}
	target := fmt.Sprintf("https://queue.untangle.com/v1/put?source=%s&type=report", uid)

	request, err := http.NewRequest("POST", target, strings.NewReader(message))
	if err != nil {
		logger.Warn("Error calling http.NewRequest: %s\n", err.Error())
		return
	}

	request.Header.Set("AuthRequest", "93BE7735-E9F2-487A-9DD4-9D05B95640F5")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Content-Length", strconv.Itoa(len(message)))

	response, err := client.Do(request)
	if err != nil {
		logger.Warn("Error calling client.Do: %s\n", err.Error())
		return
	}

	_, err = ioutil.ReadAll(response.Body)
	response.Body.Close()

	if err != nil {
		logger.Warn("Error calling ioutil.ReadAll: %s\n", err.Error())
	}

	if logger.IsDebugEnabled() {
		logger.Info("CloudURL:%s CloudRequest:%s CloudResponse: [%d] %s %s\n", target, message, response.StatusCode, response.Proto, response.Status)
	}
}
