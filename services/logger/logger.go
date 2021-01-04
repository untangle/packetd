package logger

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/untangle/packetd/services/overseer"
)

const logConfigFile = "/tmp/logconfig.js"

var logLevelName = [...]string{"EMERG", "ALERT", "CRIT", "ERROR", "WARN", "NOTICE", "INFO", "DEBUG", "TRACE"}
var logLevelMap map[string]*int32
var logLevelLocker sync.RWMutex
var launchTime time.Time
var timestampEnabled = true

//LogLevelEmerg = syslog.h/LOG_EMERG
const LogLevelEmerg int32 = 0

//LogLevelAlert = syslog.h/LOG_ALERT
const LogLevelAlert int32 = 1

//LogLevelCrit = syslog.h/LOG_CRIT
const LogLevelCrit int32 = 2

//LogLevelErr = syslog.h/LOG_ERR
const LogLevelErr int32 = 3

//LogLevelWarn = syslog.h/LOG_WARNING
const LogLevelWarn int32 = 4

//LogLevelNotice = syslog.h/LOG_NOTICE
const LogLevelNotice int32 = 5

//LogLevelInfo = syslog.h/LOG_INFO
const LogLevelInfo int32 = 6

//LogLevelDebug = syslog.h/LOG_DEBUG
const LogLevelDebug int32 = 7

//LogLevelTrace = custom value
const LogLevelTrace int32 = 8

// Startup starts the logging service
func Startup() {
	// capture startup time
	launchTime = time.Now()

	// create the map and load the Log configuration
	logLevelMap = make(map[string]*int32)
	loadLoggerConfig()

	// Set system logger to use our logger
	log.SetOutput(NewLogWriter("system"))
}

// Shutdown stops the logging service
func Shutdown() {

}

// Emerg is called for log level EMERG messages
func Emerg(format string, args ...interface{}) {
	logMessage(LogLevelEmerg, format, args...)
}

// IsEmergEnabled returns true if EMERG logging is enable for the caller
func IsEmergEnabled() bool {
	return isLogEnabled(LogLevelEmerg)
}

// Alert is called for log level ALERT messages
func Alert(format string, args ...interface{}) {
	logMessage(LogLevelAlert, format, args...)
}

// IsAlertEnabled returns true if ALERT logging is enable for the caller
func IsAlertEnabled() bool {
	return isLogEnabled(LogLevelAlert)
}

// Crit is called for log level CRIT messages
func Crit(format string, args ...interface{}) {
	logMessage(LogLevelCrit, format, args...)
}

// IsCritEnabled returns true if CRIT logging is enable for the caller
func IsCritEnabled() bool {
	return isLogEnabled(LogLevelCrit)
}

// Err is called for log level ERR messages
func Err(format string, args ...interface{}) {
	logMessage(LogLevelErr, format, args...)
}

// IsErrEnabled returns true if ERR logging is enable for the caller
func IsErrEnabled() bool {
	return isLogEnabled(LogLevelErr)
}

// Warn is called for log level WARNING messages
func Warn(format string, args ...interface{}) {
	logMessage(LogLevelWarn, format, args...)
}

// IsWarnEnabled returns true if WARNING logging is enable for the caller
func IsWarnEnabled() bool {
	return isLogEnabled(LogLevelWarn)
}

// Notice is called for log level NOTICE messages
func Notice(format string, args ...interface{}) {
	logMessage(LogLevelNotice, format, args...)
}

// IsNoticeEnabled returns true if NOTICE logging is enable for the caller
func IsNoticeEnabled() bool {
	return isLogEnabled(LogLevelNotice)
}

// Info is called for log level INFO messages
func Info(format string, args ...interface{}) {
	logMessage(LogLevelInfo, format, args...)
}

// IsInfoEnabled returns true if INFO logging is enable for the caller
func IsInfoEnabled() bool {
	return isLogEnabled(LogLevelInfo)
}

// Debug is called for log level DEBUG messages
func Debug(format string, args ...interface{}) {
	logMessage(LogLevelDebug, format, args...)
}

// IsDebugEnabled returns true if DEBUG logging is enable for the caller
func IsDebugEnabled() bool {
	return isLogEnabled(LogLevelDebug)
}

// Trace is called for log level TRACE messages
func Trace(format string, args ...interface{}) {
	logMessage(LogLevelTrace, format, args...)
}

// IsTraceEnabled returns true if TRACE logging is enable for the caller
func IsTraceEnabled() bool {
	return isLogEnabled(LogLevelTrace)
}

// LogMessageSource is for the netfilter interface functions written in C
// and our LogWriter type that can be created and passed to anything that
// expects an object with output stream support. The logging source is passed
// directly rather than determined from the call stack.
func LogMessageSource(level int32, source string, format string, args ...interface{}) {
	if level > getLogLevel(source, "") {
		return
	}

	if len(args) == 0 {
		fmt.Printf("%s%-6s %18s: %s", getPrefix(), logLevelName[level], source, format)
	} else {
		buffer := logFormatter(format, args...)
		if len(buffer) == 0 {
			return
		}
		fmt.Printf("%s%-6s %18s: %s", getPrefix(), logLevelName[level], source, buffer)
	}
}

// IsLogEnabledSource returns true if logging is enabled at the argumented level for the argumented source
func IsLogEnabledSource(level int32, source string) bool {
	lvl := getLogLevel(source, "")
	return (lvl >= level)
}

// LogWriter is used to send an output stream to the Log facility
type LogWriter struct {
	buffer []byte
	source string
}

// NewLogWriter creates an io Writer to steam output to the Log facility
func NewLogWriter(name string) *LogWriter {
	writer := new(LogWriter)
	writer.buffer = make([]byte, 0)
	writer.source = name
	return writer
}

// Write takes written data and stores it in a buffer and writes to the log when a line feed is detected
func (writer *LogWriter) Write(p []byte) (int, error) {
	for _, b := range p {
		writer.buffer = append(writer.buffer, b)
		if b == '\n' {
			LogMessageSource(LogLevelInfo, writer.source, string(writer.buffer))
			writer.buffer = make([]byte, 0)
		}
	}

	return len(p), nil
}

// EnableTimestamp enables the elapsed time in output
func EnableTimestamp() {
	timestampEnabled = true
}

// DisableTimestamp disable the elapsed time in output
func DisableTimestamp() {
	timestampEnabled = false
}

// getLogLevel returns the log level for the specified package or function
// It checks function first allowing individual functions to be configured
// for a higher level of logging than the package that owns them.
func getLogLevel(packageName string, functionName string) int32 {
	if len(functionName) != 0 {
		logLevelLocker.RLock()
		ptr, stat := logLevelMap[functionName]
		logLevelLocker.RUnlock()
		if stat == true {
			return atomic.LoadInt32(ptr)
		}
	}

	if len(packageName) != 0 {
		logLevelLocker.RLock()
		ptr, stat := logLevelMap[packageName]
		logLevelLocker.RUnlock()
		if stat == true {
			return atomic.LoadInt32(ptr)
		}
	}

	// nothing found so return default level
	return LogLevelInfo
}

// logFormatter creats a log message using the format and arguments provided
// We look for and handle special format verbs that trigger additional processing
func logFormatter(format string, args ...interface{}) string {
	// if we find the overseer counter verb the first argument is the counter name
	// the second is the log repeat limit value and the rest go to the formatter
	if strings.HasPrefix(format, "%OC|") {
		var ocname string
		var limit int64

		// make sure we have at least two arguments
		if len(args) < 2 {
			return fmt.Sprintf("ERROR: logFormatter OC verb missing arguments:%s", format)
		}

		// make sure the first argument is string
		switch args[0].(type) {
		case string:
			ocname = args[0].(string)
		default:
			return fmt.Sprintf("ERROR: logFormatter OC verb args[0] not string:%s", format)
		}

		// make sure the second argument is int
		switch args[1].(type) {
		case int:
			limit = int64(args[1].(int))
		default:
			return fmt.Sprintf("ERROR: logFormatter OC verb args[1] not int:%s", format)
		}

		total := overseer.AddCounter(ocname, 1)

		// only format the message on the first and every nnn messages thereafter
		// or if limit is zero which means no limit on logging
		if total == 1 || limit == 0 || (total%limit) == 0 {
			// if there are only two arguments everything after the verb is the message
			if len(args) == 2 {
				return format[4:]
			}

			// more than two arguments so use the remaining format and arguments
			return fmt.Sprintf(format[4:], args[2:]...)
		}

		// return empty string when a repeat is limited
		return ""
	}

	buffer := fmt.Sprintf(format, args...)
	return buffer
}

// isLogEnabled returns true if logging is enabled for the caller at the specified level, false otherwise
func isLogEnabled(level int32) bool {
	_, _, packageName, functionName := findCallingFunction()
	if IsLogEnabledSource(level, packageName) {
		return true
	}
	if IsLogEnabledSource(level, functionName) {
		return true
	}
	return false
}

// logMessage is called to write messages to the system log
func logMessage(level int32, format string, args ...interface{}) {
	_, _, packageName, functionName := findCallingFunction()

	if level > getLogLevel(packageName, functionName) {
		return
	}

	if len(args) == 0 {
		fmt.Printf("%s%-6s %18s: %s", getPrefix(), logLevelName[level], packageName, format)
	} else {
		buffer := logFormatter(format, args...)
		if len(buffer) == 0 {
			return
		}
		fmt.Printf("%s%-6s %18s: %s", getPrefix(), logLevelName[level], packageName, buffer)
	}
}

// loadLoggerConfig loads the logger configuration file
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
			// if the string matches the level will be the index of the matched name
			if strings.Compare(levelname, strings.ToUpper(cfglevel)) == 0 {
				logLevelMap[cfgname] = new(int32)
				atomic.StoreInt32(logLevelMap[cfgname], int32(levelvalue))
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

	// make a map and fill it with a default log level for every package
	config := make(map[string]string)
	config["_FileVersion_"] = "200"
	config["_ValidLevels_"] = comment

	// plugins
	config["certfetch"] = "INFO"
	config["certsniff"] = "INFO"
	config["classify"] = "INFO"
	config["dns"] = "INFO"
	config["example"] = "INFO"
	config["geoip"] = "INFO"
	config["predicttraffic"] = "INFO"
	config["reporter"] = "INFO"
	config["revdns"] = "INFO"
	config["sni"] = "INFO"
	config["stats"] = "INFO"

	// services
	config["certcache"] = "INFO"
	config["certmanager"] = "INFO"
	config["dict"] = "INFO"
	config["dispatch"] = "INFO"
	config["kernel"] = "INFO"
	config["logger"] = "INFO"
	config["netspace"] = "INFO"
	config["overseer"] = "INFO"
	config["predicttrafficsvc"] = "INFO"
	config["reports"] = "INFO"
	config["restd"] = "INFO"
	config["settings"] = "INFO"

	// static source names used in the low level c handlers
	config["common"] = "INFO"
	config["conntrack"] = "INFO"
	config["netlogger"] = "INFO"
	config["nfqueue"] = "INFO"
	config["warehouse"] = "INFO"
	config["system"] = "INFO"
	config["gin"] = "INFO"

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

// This function uses runtime.Callers to get the call stack to determine the calling function
// Our public function heirarchy is implemented so the caller is always at the 5th frame
// Frame 0 = runtime.Callers
// Frame 1 = findCallingFunction
// Frame 2 = logMessage / isLogEnabled
// Frame 3 = Warn, Info / IsWarnEnabled, IsInfoEnabled (etc...)
// Frame 4 = the function that actually called logger.Warn, logger.Info, logger.IsWarnEnabled, logger.IsInfoEnabled, etc...

// Here is an example of what we expect to see in the calling function frame:
// FILE: /home/username/golang/src/github.com/untangle/packetd/services/dict/dict.go
// FUNC: github.com/untangle/packetd/services/dict.cleanDictionary
// LINE: 827
// We find the last / in caller.Function and use the entire string as the function name (dict.cleanDictionary)
// We find the dot in the function name and use the left side as the package name (dict)
func findCallingFunction() (string, int, string, string) {
	// create a single entry array to hold the 5th stack frame and pass 4 as the
	// number of frames to skip over so we get the single stack frame we need
	stack := make([]uintptr, 1)
	count := runtime.Callers(4, stack)
	if count != 1 {
		return "unknown", 0, "unknown", "unknown"
	}

	// get the frame object for the caller
	frames := runtime.CallersFrames(stack)
	caller, _ := frames.Next()

	var functionName string
	var packageName string

	// Find the index of the last slash to isolate the package.FunctionName
	end := strings.LastIndex(caller.Function, "/")
	if end < 0 {
		functionName = caller.Function
	} else {
		functionName = caller.Function[end+1:]
	}

	// Find the index of the dot after the package name
	dot := strings.Index(functionName, ".")
	if dot < 0 {
		packageName = "unknown"
	} else {
		packageName = functionName[0:dot]
	}

	return caller.File, caller.Line, packageName, functionName
}

// getPrefix returns a log message prefix
func getPrefix() string {
	if !timestampEnabled {
		return ""
	}

	nowtime := time.Now()
	var elapsed = nowtime.Sub(launchTime)
	return fmt.Sprintf("[%11.5f] ", elapsed.Seconds())
}

// SearchSourceLogLevel returns the log level for the specified source
// or a negative value if the source does not exist
func SearchSourceLogLevel(source string) int32 {
	logLevelLocker.RLock()
	ptr, stat := logLevelMap[source]
	logLevelLocker.RUnlock()
	if stat == false {
		return -1
	}

	return atomic.LoadInt32(ptr)
}

// AdjustSourceLogLevel sets the log level for the specified source and returns
// the previous level or a negative value if the source does not exist
func AdjustSourceLogLevel(source string, level int32) int32 {
	logLevelLocker.RLock()
	ptr, stat := logLevelMap[source]
	logLevelLocker.RUnlock()
	if stat == false {
		Notice("Adding log level source NAME:%s LEVEL:%d\n", source, level)
		ptr = new(int32)
		atomic.StoreInt32(ptr, -1)
		logLevelLocker.Lock()
		logLevelMap[source] = ptr
		logLevelLocker.Unlock()
	}

	prelvl := atomic.LoadInt32(ptr)
	atomic.StoreInt32(ptr, level)
	return prelvl
}

// FindLogLevelValue returns the numeric log level for the arugmented name
// or a negative value if the level is not valid
func FindLogLevelValue(source string) int32 {
	for levelvalue, levelname := range logLevelName {
		if strings.Compare(strings.ToUpper(levelname), strings.ToUpper(source)) == 0 {
			return (int32(levelvalue))
		}
	}

	return -1
}

// FindLogLevelName returns the log level name for the argumented value
func FindLogLevelName(level int32) string {
	if level < 0 {
		return "UNDEFINED"
	}
	if int(level) > len(logLevelName) {
		return fmt.Sprintf("%d", level)
	}
	return logLevelName[level]
}

// GenerateReport is called to create a dynamic HTTP page that shows all debug sources
func GenerateReport(buffer *bytes.Buffer) {
	logLevelLocker.RLock()
	defer logLevelLocker.RUnlock()

	// create a sorted list of the log level names
	namelist := make([]string, 0, len(logLevelMap))
	for name := range logLevelMap {
		namelist = append(namelist, name)
	}
	sort.Strings(namelist)

	buffer.WriteString("<TABLE BORDER=2 CELLPADDING=4 BGCOLOR=#EEEEEE>\r\n")
	buffer.WriteString("<TR><TH COLSPAN=2>Logger Source Levels</TH></TR>\r\n")
	buffer.WriteString("<TR><TD><B>Logger Source</B></TD><TD><B>Log Level</B></TD></TR>\r\n")

	for _, name := range namelist {
		ptr := logLevelMap[name]
		buffer.WriteString("<TR><TD><TT>")
		buffer.WriteString(name)
		buffer.WriteString("</TT></TD><TD><TT>")
		buffer.WriteString(FindLogLevelName(atomic.LoadInt32(ptr)))
		buffer.WriteString("</TT></TD></TR>\n\n")
	}

	buffer.WriteString("</TABLE>\r\n")
}
