package logger

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

const logConfigFile = "/tmp/logconfig.js"

var logLevelName = [...]string{"EMERG", "ALERT", "CRIT", "ERROR", "WARN", "NOTICE", "INFO", "DEBUG", "LOGIC"}
var appLogLevel map[string]int
var launchTime time.Time
var appname = "logger"

//LogEmerg = stdlog.h/LOG_EMERG
const LogEmerg = 0

//LogAlert = stdlog.h/LOG_ALERT
const LogAlert = 1

//LogCrit = stdlog.h/LOG_CRIT
const LogCrit = 2

//LogErr = stdlog.h/LOG_ERR
const LogErr = 3

//LogWarn = stdlog.h/LOG_WARNING
const LogWarn = 4

//LogNotice = stdlog.h/LOG_NOTICE
const LogNotice = 5

//LogInfo = stdlog.h/LOG_INFO
const LogInfo = 6

//LogDebug = stdlog.h/LOG_DEBUG
const LogDebug = 7

//LogLogic = custom value
const LogLogic = 8

// Startup starts the logging service
func Startup() {
	// capture startup time
	launchTime = time.Now()

	// create the map and load the LogMessage configuration
	appLogLevel = make(map[string]int)
	loadLoggerConfig()

	// Set system logger to use our logger
	log.SetOutput(NewLogWriter("log"))
}

// Shutdown stops the logging service
func Shutdown() {

}

// LogMessage is called to write messages to the system log
func LogMessage(level int, source string, format string, args ...interface{}) {
	var ignore bool

	item, stat := appLogLevel[source]
	if stat == true {
		if item < level {
			ignore = true
		}
	}

	if ignore == true {
		return
	}

	nowtime := time.Now()
	var elapsed = nowtime.Sub(launchTime)

	if len(args) == 0 {
		fmt.Printf("[%11.5f] %-6s %10s: %s", elapsed.Seconds(), logLevelName[level], source, format)
	} else {
		buffer := fmt.Sprintf(format, args...)
		fmt.Printf("[%11.5f] %-6s %10s: %s", elapsed.Seconds(), logLevelName[level], source, buffer)
	}
}

// LogWriter is used to send an output stream to the LogMessage facility
type LogWriter struct {
	source string
	buffer []byte
}

// NewLogWriter creates an io Writer to steam output to the LogMessage facility
func NewLogWriter(source string) *LogWriter {
	return (&LogWriter{source, make([]byte, 256)})
}

// Write takes written data and stores it in a buffer and writes to the log when a line feed is detected
func (w *LogWriter) Write(p []byte) (int, error) {
	for _, b := range p {
		w.buffer = append(w.buffer, b)
		if b == '\n' {
			LogMessage(LogInfo, w.source, string(w.buffer))
			w.buffer = make([]byte, 256)
		}
	}

	return len(p), nil
}

func loadLoggerConfig() {
	var file *os.File
	var info os.FileInfo
	var err error

	// open the logger configuration file
	file, err = os.Open(logConfigFile)

	// if there was an error create the config and try the open again
	if err != nil {
		initLoggerConfig()
		file, err = os.Open(logConfigFile)

		// if there is still an error we are out of options
		if err != nil {
			LogMessage(LogErr, appname, "Unable to load LogMessage configuration file: %s\n", logConfigFile)
			return
		}
	}

	// make sure the file gets closed
	defer file.Close()

	// get the file status
	info, err = file.Stat()
	if err != nil {
		LogMessage(LogErr, appname, "Unable to query file information\n")
		return
	}

	// read the raw configuration json from the file
	config := make(map[string]string)
	var data = make([]byte, info.Size())
	len, err := file.Read(data)

	if (err != nil) || (len < 1) {
		LogMessage(LogErr, appname, "Unable to read LogMessage configuration\n")
		return
	}

	// unmarshal the configuration into a map
	err = json.Unmarshal(data, &config)
	if err != nil {
		LogMessage(LogErr, appname, "Unable to parse LogMessage configuration\n")
		return
	}

	// put the name/string pairs from the file into the name/int lookup map we us in the LogMessage function
	for cfgname, cfglevel := range config {
		// ignore any comment strings that start and end with underscore
		if strings.HasPrefix(cfgname, "_") && strings.HasSuffix(cfgname, "_") {
			continue
		}

		// find the index of the logLevelName that matches the configured level
		found := false
		for levelvalue, levelname := range logLevelName {
			if strings.Compare(levelname, strings.ToUpper(cfglevel)) == 0 {
				appLogLevel[cfgname] = levelvalue
				found = true
			}
		}
		if found == false {
			LogMessage(LogWarn, appname, "Invalid LogMessage configuration entry: %s=%s\n", cfgname, cfglevel)
		}
	}
}

func initLoggerConfig() {
	LogMessage(LogAlert, appname, "LogMessage configuration not found. Creating default file: %s\n", logConfigFile)

	// create a comment that shows all valid log level names
	var comment string
	for item, element := range logLevelName {
		if item != 0 {
			comment += "|"
		}
		comment += element
	}

	// make a map and fill it with a default log level for every application
	config := make(map[string]string)
	config["_ValidLevels_"] = comment
	config["certcache"] = "INFO"
	config["classify"] = "INFO"
	config["conndict"] = "INFO"
	config["conntrack"] = "INFO"
	config["dns"] = "INFO"
	config["example"] = "INFO"
	config["events"] = "INFO"
	config["geoip"] = "INFO"
	config["kernel"] = "INFO"
	config["logger"] = "INFO"
	config["nfqueue"] = "INFO"
	config["netlogger"] = "INFO"
	config["packetd"] = "INFO"
	config["reports"] = "INFO"
	config["restd"] = "INFO"
	config["settings"] = "INFO"

	// convert the config map to a json object
	jstr, err := json.MarshalIndent(config, "", "")
	if err != nil {
		LogMessage(LogAlert, appname, "LogMessage failure creating default configuration: %s\n", err.Error())
		return
	}

	// create the logger configuration file
	file, err := os.Create(logConfigFile)
	if err != nil {
		return
	}

	// write the default configuration and close the file
	file.Write(jstr)
	file.Close()
}
