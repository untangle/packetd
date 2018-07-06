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

var logLevelName = [...]string{"EMERG", "ALERT", "CRIT", "ERROR", "WARN", "NOTICE", "INFO", "DEBUG", "TRACE"}
var appLogLevel map[string]int
var launchTime time.Time
var logsrc = "logger"

//LogLevelEmerg = stdlog.h/LOG_EMERG
const LogLevelEmerg = 0

//LogLevelAlert = stdlog.h/LOG_ALERT
const LogLevelAlert = 1

//LogLevelCrit = stdlog.h/LOG_CRIT
const LogLevelCrit = 2

//LogLevelErr = stdlog.h/LOG_ERR
const LogLevelErr = 3

//LogLevelWarn = stdlog.h/LOG_WARNING
const LogLevelWarn = 4

//LogLevelNotice = stdlog.h/LOG_NOTICE
const LogLevelNotice = 5

//LogLevelInfo = stdlog.h/LOG_INFO
const LogLevelInfo = 6

//LogLevelDebug = stdlog.h/LOG_DEBUG
const LogLevelDebug = 7

//LogLevelTrace = custom value
const LogLevelTrace = 8

// Startup starts the logging service
func Startup() {
	// capture startup time
	launchTime = time.Now()

	// create the map and load the Log configuration
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

// IsLogEnabled retruns true if logging is enabled for the specified source at the specified level, false otherwise
func IsLogEnabled(source string, level int) bool {
	item, stat := appLogLevel[source]
	if stat == true {
		return (item >= level)
	} else {
		return false
	}
}

// LogEmerg is called for log level EMERG messages
func LogEmerg(source string, format string, args ...interface{}) {
	LogMessage(LogLevelEmerg, source, format, args...)
}

// IsEmergEnabled returns true if EMERG logging is enable for the specified source
func IsEmergEnabled(source string) bool {
	return IsLogEnabled(source, LogLevelEmerg)
}

// LogAlert is called for log level ALERT messages
func LogAlert(source string, format string, args ...interface{}) {
	LogMessage(LogLevelAlert, source, format, args...)
}

// IsAlertEnabled returns true if ALERT logging is enable for the specified source
func IsAlertEnabled(source string) bool {
	return IsLogEnabled(source, LogLevelAlert)
}

// LogCrit is called for log level CRIT messages
func LogCrit(source string, format string, args ...interface{}) {
	LogMessage(LogLevelCrit, source, format, args...)
}

// IsCritEnabled returns true if CRIT logging is enable for the specified source
func IsCritEnabled(source string) bool {
	return IsLogEnabled(source, LogLevelCrit)
}

// LogErr is called for log level ERR messages
func LogErr(source string, format string, args ...interface{}) {
	LogMessage(LogLevelErr, source, format, args...)
}

// IsErrEnabled returns true if ERR logging is enable for the specified source
func IsErrEnabled(source string) bool {
	return IsLogEnabled(source, LogLevelErr)
}

// LogWarn is called for log level WARN messages
func LogWarn(source string, format string, args ...interface{}) {
	LogMessage(LogLevelWarn, source, format, args...)
}

// IsWarnEnabled returns true if WARN logging is enable for the specified source
func IsWarnEnabled(source string) bool {
	return IsLogEnabled(source, LogLevelWarn)
}

// LogNotice is called for log level NOTICE messages
func LogNotice(source string, format string, args ...interface{}) {
	LogMessage(LogLevelNotice, source, format, args...)
}

// IsNoticeEnabled returns true if NOTICE logging is enable for the specified source
func IsNoticeEnabled(source string) bool {
	return IsLogEnabled(source, LogLevelNotice)
}

// LogInfo is called for log level INFO messages
func LogInfo(source string, format string, args ...interface{}) {
	LogMessage(LogLevelInfo, source, format, args...)
}

// IsInfoEnabled returns true if INFO logging is enable for the specified source
func IsInfoEnabled(source string) bool {
	return IsLogEnabled(source, LogLevelInfo)
}

// LogDebug is called for log level DEBUG messages
func LogDebug(source string, format string, args ...interface{}) {
	LogMessage(LogLevelDebug, source, format, args...)
}

// IsDebugEnabled returns true if DEBUG logging is enable for the specified source
func IsDebugEnabled(source string) bool {
	return IsLogEnabled(source, LogLevelDebug)
}

// LogTrace is called for log level TRACE messages
func LogTrace(source string, format string, args ...interface{}) {
	LogMessage(LogLevelTrace, source, format, args...)
}

// IsTraceEnabled returns true if TRACE logging is enable for the specified source
func IsTraceEnabled(source string) bool {
	return IsLogEnabled(source, LogLevelTrace)
}

// LogWriter is used to send an output stream to the Log facility
type LogWriter struct {
	source string
	buffer []byte
}

// NewLogWriter creates an io Writer to steam output to the Log facility
func NewLogWriter(source string) *LogWriter {
	return (&LogWriter{source, make([]byte, 256)})
}

// Write takes written data and stores it in a buffer and writes to the log when a line feed is detected
func (w *LogWriter) Write(p []byte) (int, error) {
	for _, b := range p {
		w.buffer = append(w.buffer, b)
		if b == '\n' {
			LogInfo(w.source, string(w.buffer))
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
			LogErr(logsrc, "Unable to load Log configuration file: %s\n", logConfigFile)
			return
		}
	}

	// make sure the file gets closed
	defer file.Close()

	// get the file status
	info, err = file.Stat()
	if err != nil {
		LogErr(logsrc, "Unable to query file information\n")
		return
	}

	// read the raw configuration json from the file
	config := make(map[string]string)
	var data = make([]byte, info.Size())
	len, err := file.Read(data)

	if (err != nil) || (len < 1) {
		LogErr(logsrc, "Unable to read Log configuration\n")
		return
	}

	// unmarshal the configuration into a map
	err = json.Unmarshal(data, &config)
	if err != nil {
		LogErr(logsrc, "Unable to parse Log configuration\n")
		return
	}

	// put the name/string pairs from the file into the name/int lookup map we us in the Log function
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
			LogWarn(logsrc, "Invalid Log configuration entry: %s=%s\n", cfgname, cfglevel)
		}
	}
}

func initLoggerConfig() {
	LogAlert(logsrc, "Log configuration not found. Creating default file: %s\n", logConfigFile)

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

	// plugins
	config["certcache"] = "INFO"
	config["classify"] = "INFO"
	config["dns"] = "INFO"
	config["geoip"] = "INFO"
	config["example"] = "INFO"
	config["reporter"] = "INFO"
	config["sni"] = "INFO"

	// services
	config["dict"] = "INFO"
	config["conntrack"] = "INFO"
	config["dispatch"] = "INFO"
	config["exec"] = "INFO"
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
		LogAlert(logsrc, "Log failure creating default configuration: %s\n", err.Error())
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
