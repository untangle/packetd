package appclassmanager

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"io"
	"os"
	"strconv"

	"github.com/untangle/packetd/services/logger"
)

// applicationInfo stores the details for each know application
type ApplicationInfo struct {
	Guid         string `json:"guid"`
	Index        int    `json:"index"`
	Name         string `json:"name"`
	Description  string `json:"description"`
	Category     string `json:"category"`
	Productivity uint8  `json:"productivity"`
	Risk         uint8  `json:"risk"`
	Flags        uint64 `json:"flags"`
	Reference    string `json:"reference"`
	Plugin       string `json:"plugin"`
}

// Category info contains details about a category (used when converting ApplicationTable to categories for extjs store)
type CategoryInfo struct {
	Name string `json:"name"`
}

const guidInfoFile = "/usr/share/untangle-classd/protolist.csv"

var ApplicationTable map[string]*ApplicationInfo

// Startup is called when the packetd service starts
func Startup() {
	logger.Info("Starting up the Application Classification Table manager service\n")
	loadApplicationTable()

}

// Shutdown is called when the packetd service stops
func Shutdown() {
	logger.Info("Shutting down the Application Classification Table manager service\n")
}

// GetApplicationTable returns the application table as JSON
func GetApplicationTable() (string, error) {
	logger.Debug("Getting application table...\n")

	// convert it to a slice first
	appTable := []*ApplicationInfo{}

	for _, val := range ApplicationTable {
		appTable = append(appTable, val)
	}

	jsonData, err := json.Marshal(appTable)

	if err != nil {
		logger.Err("Unable to get ClassD application table: %s\n", err.Error())
		return "", err
	}

	return string(jsonData), nil
}

// GetCategoryTable returns a distinct list of the categories we currently have in the ApplicationTable
func GetCategoryTable() (string, error) {
	logger.Debug("Getting Category table...\n")

	// Instead of two loops, create a map that indicates if the items exist in the slice
	catMap := make(map[string]bool)
	catSlice := []*CategoryInfo{}

	// Iterate the table, if the map contains the slice then continue, otherwise add it to the map
	for _, val := range ApplicationTable {
		if catMap[val.Category] {
			continue
		}

		catSlice = append(catSlice, &CategoryInfo{Name: val.Category})
		catMap[val.Category] = true
	}

	// Now convert the slice of CategoryInfo into JSON
	jsonData, err := json.Marshal(catSlice)

	if err != nil {
		logger.Err("Unable to get ClassD Category table: %s\n", err.Error())
		return "", err
	}

	return string(jsonData), nil

}

// loadApplicationTable loads the details for each application
func loadApplicationTable() {
	var file *os.File
	var linecount int
	var infocount int
	var list []string
	var err error

	ApplicationTable = make(map[string]*ApplicationInfo)

	// open the guid info file provided by Sandvine
	file, err = os.Open(guidInfoFile)

	// if there was an error log and return
	if err != nil {
		logger.Warn("Unable to load application details: %s\n", guidInfoFile)
		return
	}

	// create a new CSV reader
	reader := csv.NewReader(bufio.NewReader(file))
	for {
		list, err = reader.Read()

		if err == io.EOF {
			// on end of file just break out of the read loop
			break
		} else if err != nil {
			// for anything else log the error and break
			logger.Err("Unable to parse application details: %v\n", err)
			break
		}

		// count the number of lines read so we can compare with
		// the number successfully parsed when we finish loading
		linecount++

		// skip the first line that holds the file format description
		if linecount == 1 {
			continue
		}

		// if we did not parse exactly 10 fields skip the line
		if len(list) != 10 {
			logger.Warn("Invalid line length: %d\n", len(list))
			continue
		}

		// create a object to store the details
		info := new(ApplicationInfo)

		info.Guid = list[0]
		info.Index, err = strconv.Atoi(list[1])
		if err != nil {
			logger.Warn("Invalid index: %s\n", list[1])
		}
		info.Name = list[2]
		info.Description = list[3]
		info.Category = list[4]
		tempProd, err := strconv.ParseUint(list[5], 10, 8)
		if err != nil {
			logger.Warn("Invalid productivity: %s\n", list[5])
		}
		info.Productivity = uint8(tempProd)
		tempRisk, err := strconv.ParseUint(list[6], 10, 8)
		if err != nil {
			logger.Warn("Invalid risk: %s\n", list[6])
		}
		info.Risk = uint8(tempRisk)
		info.Flags, err = strconv.ParseUint(list[7], 10, 64)
		if err != nil {
			logger.Warn("Invalid flags: %s %s\n", list[7], err)
		}
		info.Reference = list[8]
		info.Plugin = list[9]

		// store the object in the table using the guid as the index
		ApplicationTable[info.Guid] = info
		infocount++
	}

	file.Close()
	logger.Info("Loaded classification details for %d applications\n", infocount)

	// if there were any bad lines in the file log a warning
	if infocount != linecount-1 {
		logger.Warn("Detected garbage in the application info file: %s\n", guidInfoFile)
	}
}
