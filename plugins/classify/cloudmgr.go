// Package classify classifies sessions as certain applications
// each packet gets sent to a classd daemon (the categorization engine)
// the classd daemon returns the classification information and classify
// attaches the information to the session.
package classify

import (
	"time"

	"github.com/untangle/packetd/services/logger"
)

// pluginCloudManager is a goroutine to handle the daemon socket connection
func pluginCloudManager() {
	logger.Info("The pluginCloudManager is starting\n")

	for {
		select {
		case message := <-cloudChannel:
			if message == systemShutdown {
				shutdownChannel <- true
				logger.Info("The pluginCloudManager is finished\n")
				return
			}
		case <-time.After(60 * time.Second):
			logger.Info("Sending updates to the cloud\n")
		}
	}
}
