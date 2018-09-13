package logger

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"time"
)

const logConfigFile = "/tmp/logconfig.js"

var logLevelName = [...]string{"EMERG", "ALERT", "CRIT", "ERROR", "WARN", "NOTIC", "INFO", "DEBUG", "TRACE"}
var appLogLevel map[string]int
var launchTime time.Time

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
	log.SetOutput(NewLogWriter())
}

// Shutdown stops the logging service
func Shutdown() {

}

// LogMessage is called to write messages to the system log
func LogMessage(level int, format string, args ...interface{}) {
	caller, packagename, _, _ := findCaller()

	// if no log level defined, assume Info
	var loglvl = LogLevelInfo

	item, stat := appLogLevel[packagename]
	if stat == true {
		loglvl = item
	}
	if level > loglvl {
		return
	}

	nowtime := time.Now()
	var elapsed = nowtime.Sub(launchTime)

	if len(args) == 0 {
		fmt.Printf("[%11.5f] %-5s %26s: %s", elapsed.Seconds(), logLevelName[level], caller, format)
	} else {
		buffer := fmt.Sprintf(format, args...)
		fmt.Printf("[%11.5f] %-5s %26s: %s", elapsed.Seconds(), logLevelName[level], caller, buffer)
	}
}

// LogMessageSource is similar to LogMessage
// except instead of using runtime to determine the caller/source
// the source is specified manually
func LogMessageSource(level int, source string, format string, args ...interface{}) {
	// if no log level defined, assume Info
	var loglvl = LogLevelInfo

	item, stat := appLogLevel[source]
	if stat == true {
		loglvl = item
	}
	if level > loglvl {
		return
	}

	nowtime := time.Now()
	var elapsed = nowtime.Sub(launchTime)

	if len(args) == 0 {
		fmt.Printf("[%11.5f] %-5s %26s: %s", elapsed.Seconds(), logLevelName[level], source, format)
	} else {
		buffer := fmt.Sprintf(format, args...)
		fmt.Printf("[%11.5f] %-5s %26s: %s", elapsed.Seconds(), logLevelName[level], source, buffer)
	}
}

// IsLogEnabled returns true if logging is enabled for the caller at the specified level, false otherwise
func IsLogEnabled(level int) bool {
	_, packagename, _, _ := findCaller()
	return IsLogEnabledSource(level, packagename)
}

// IsLogEnabledSource is the same as IsLogEnabled but for the manually specified source
func IsLogEnabledSource(level int, source string) bool {
	item, stat := appLogLevel[source]
	if stat == true {
		return (item >= level)
	}
	return false
}

// Emerg is called for log level EMERG messages
func Emerg(format string, args ...interface{}) {
	LogMessage(LogLevelEmerg, format, args...)
}

// IsEmergEnabled returns true if EMERG logging is enable for the caller
func IsEmergEnabled() bool {
	return IsLogEnabled(LogLevelEmerg)
}

// Alert is called for log level ALERT messages
func Alert(format string, args ...interface{}) {
	LogMessage(LogLevelAlert, format, args...)
}

// IsAlertEnabled returns true if ALERT logging is enable for the caller
func IsAlertEnabled() bool {
	return IsLogEnabled(LogLevelAlert)
}

// Crit is called for log level CRIT messages
func Crit(format string, args ...interface{}) {
	LogMessage(LogLevelCrit, format, args...)
}

// IsCritEnabled returns true if CRIT logging is enable for the caller
func IsCritEnabled() bool {
	return IsLogEnabled(LogLevelCrit)
}

// Err is called for log level ERR messages
func Err(format string, args ...interface{}) {
	LogMessage(LogLevelErr, format, args...)
}

// IsErrEnabled returns true if ERR logging is enable for the caller
func IsErrEnabled() bool {
	return IsLogEnabled(LogLevelErr)
}

// Warn is called for log level WARN messages
func Warn(format string, args ...interface{}) {
	LogMessage(LogLevelWarn, format, args...)
}

// IsWarnEnabled returns true if WARN logging is enable for the caller
func IsWarnEnabled() bool {
	return IsLogEnabled(LogLevelWarn)
}

// Notice is called for log level NOTICE messages
func Notice(format string, args ...interface{}) {
	LogMessage(LogLevelNotice, format, args...)
}

// IsNoticeEnabled returns true if NOTICE logging is enable for the caller
func IsNoticeEnabled() bool {
	return IsLogEnabled(LogLevelNotice)
}

// Info is called for log level INFO messages
func Info(format string, args ...interface{}) {
	LogMessage(LogLevelInfo, format, args...)
}

// IsInfoEnabled returns true if INFO logging is enable for the caller
func IsInfoEnabled() bool {
	return IsLogEnabled(LogLevelInfo)
}

// Debug is called for log level DEBUG messages
func Debug(format string, args ...interface{}) {
	LogMessage(LogLevelDebug, format, args...)
}

// IsDebugEnabled returns true if DEBUG logging is enable for the caller
func IsDebugEnabled() bool {
	return IsLogEnabled(LogLevelDebug)
}

// Trace is called for log level TRACE messages
func Trace(format string, args ...interface{}) {
	LogMessage(LogLevelTrace, format, args...)
}

// IsTraceEnabled returns true if TRACE logging is enable for the caller
func IsTraceEnabled() bool {
	return IsLogEnabled(LogLevelTrace)
}

// LogWriter is used to send an output stream to the Log facility
type LogWriter struct {
	buffer []byte
}

// NewLogWriter creates an io Writer to steam output to the Log facility
func NewLogWriter() *LogWriter {
	return (&LogWriter{make([]byte, 0)})
}

// Write takes written data and stores it in a buffer and writes to the log when a line feed is detected
func (w *LogWriter) Write(p []byte) (int, error) {
	for _, b := range p {
		w.buffer = append(w.buffer, b)
		if b == '\n' {
			Info(string(w.buffer))
			w.buffer = make([]byte, 0)
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
			Err("Unable to load Log configuration file: %s\n", logConfigFile)
			return
		}
	}

	// make sure the file gets closed
	defer file.Close()

	// get the file status
	info, err = file.Stat()
	if err != nil {
		Err("Unable to query file information\n")
		return
	}

	// read the raw configuration json from the file
	config := make(map[string]string)
	var data = make([]byte, info.Size())
	len, err := file.Read(data)

	if (err != nil) || (len < 1) {
		Err("Unable to read Log configuration\n")
		return
	}

	// unmarshal the configuration into a map
	err = json.Unmarshal(data, &config)
	if err != nil {
		Err("Unable to parse Log configuration\n")
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
			Warn("Invalid Log configuration entry: %s=%s\n", cfgname, cfglevel)
		}
	}
}

func initLoggerConfig() {
	Alert("Log configuration not found. Creating default file: %s\n", logConfigFile)

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
	config["dispatch"] = "INFO"
	config["dispatch_timer"] = "INFO"
	config["exec"] = "INFO"
	config["kernel"] = "INFO"
	config["logger"] = "INFO"
	config["packetd"] = "INFO"
	config["reports"] = "INFO"
	config["restd"] = "INFO"
	config["settings"] = "INFO"

	// convert the config map to a json object
	jstr, err := json.MarshalIndent(config, "", "")
	if err != nil {
		Alert("Log failure creating default configuration: %s\n", err.Error())
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

func findCaller() (string, string, string, int) {
	// start with 1 because this is not public
	for depth := 1; depth < 15; depth++ {
		_, filename, line, ok := runtime.Caller(depth)
		if ok && !strings.HasSuffix(filename, "logger.go") && !strings.HasSuffix(filename, "log.go") {
			var split = strings.Split(filename, "/")
			var shortname string
			if len(split) > 1 {
				shortname = split[len(split)-1]
			} else {
				shortname = filename
			}
			//shortname = strings.TrimSuffix(shortname, ".go")

			var packagename string
			if len(split) > 2 {
				packagename = split[len(split)-2]
			} else {
				packagename = shortname
			}

			var summary = fmt.Sprintf("%s/%s:%04d", packagename, shortname, line)
			if len(summary) > 26 {
				summary = summary[len(summary)-26:]
			}
			return summary, packagename, shortname, line
		}
	}

	return "unknown|unknown:0", "unknown:0", "unknown", 0
}
