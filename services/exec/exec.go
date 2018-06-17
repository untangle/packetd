package exec

import (
	"github.com/untangle/packetd/services/logger"
	"os/exec"
)

var appname = "exec"

// Startup is called during daemon startup to handle initialization
func Startup() {
}

// Shutdown any support services
func Shutdown() {
}

// Run a system command
func SystemCommand(command string, arguments []string) ([]byte, error) {
	var result []byte
	var err error

	result, err = exec.Command(command, arguments...).CombinedOutput()
	if err != nil {
		logger.LogMessage(logger.LogInfo, appname, "COMMAND:%s | OUTPUT:%s | ERROR:%s\n", command, string(result), err.Error())
	} else {
		logger.LogMessage(logger.LogDebug, appname, "COMMAND:%s | OUTPUT:%s\n", command, string(result))
	}
	return result, err
}
