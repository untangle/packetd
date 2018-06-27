package exec

import (
	"github.com/untangle/packetd/services/logger"
	"os/exec"
	"strings"
)

var logsrc = "exec"

// Startup is called during daemon startup to handle initialization
func Startup() {
}

// Shutdown any support services
func Shutdown() {
}

// SystemCommand runs a system command
func SystemCommand(command string, arguments []string) ([]byte, error) {
	var result []byte
	var err error

	result, err = exec.Command(command, arguments...).CombinedOutput()
	if err != nil {
		logger.LogInfo(logsrc, "COMMAND:%s | OUTPUT:%s | ERROR:%s\n", command, strings.TrimSpace(string(result)), err.Error())
	} else {
		logger.LogDebug(logsrc, "COMMAND:%s | OUTPUT:%s\n", command, string(result))
	}
	return result, err
}
