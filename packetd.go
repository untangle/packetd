package main

import (
	"flag"
	"github.com/untangle/packetd/plugins/certcache"
	"github.com/untangle/packetd/plugins/classify"
	"github.com/untangle/packetd/plugins/dns"
	"github.com/untangle/packetd/plugins/example"
	"github.com/untangle/packetd/plugins/geoip"
	"github.com/untangle/packetd/services/conndict"
	"github.com/untangle/packetd/services/dispatch"
	"github.com/untangle/packetd/services/exec"
	"github.com/untangle/packetd/services/kernel"
	"github.com/untangle/packetd/services/logger"
	"github.com/untangle/packetd/services/reports"
	"github.com/untangle/packetd/services/restd"
	"github.com/untangle/packetd/services/settings"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// The pluginSync is used to give the main process something to watch while
// waiting for all of the goroutine children to finish execution and cleanup.
var pluginSync sync.WaitGroup
var appname = "packetd"
var exitLock sync.Mutex

func main() {
	var classdPtr = flag.String("classd", "127.0.0.1:8123", "host:port for classd daemon")
	flag.Parse()

	handleSignals()

	// Start services
	logger.Startup()
	kernel.Startup()
	dispatch.Startup()
	exec.Startup()
	settings.Startup()
	reports.Startup()
	conndict.Startup()

	// Start all the callbacks
	kernel.StartCallbacks()

	// Start Plugins
	go example.PluginStartup(&pluginSync)
	go classify.PluginStartup(&pluginSync, classdPtr)
	go geoip.PluginStartup(&pluginSync)
	go certcache.PluginStartup(&pluginSync)
	go dns.PluginStartup(&pluginSync)

	// Start REST HTTP daemon
	go restd.Startup()

	// Insert netfilter rules
	updateRules()

	logger.LogMessage(logger.LogInfo, appname, "Untangle Packet Daemon Version %s\n", "1.00")

	// Check that all the C services started correctly
	// This flag is only set on Startup so this only needs to be checked once
	time.Sleep(1)
	if kernel.GetShutdownFlag() != 0 {
		cleanup()
		os.Exit(0)
	}

	// Loop forever
	for {
		time.Sleep(60 * time.Second)
		logger.LogMessage(logger.LogInfo, appname, ".\n")
	}
}

// Cleanup packetd and exit
func cleanup() {
	// Prevent further calls
	exitLock.Lock()

	// Remove netfilter rules
	logger.LogMessage(logger.LogInfo, appname, "Removing netfilter rules...\n")
	removeRules()

	// Stop kernel callbacks
	logger.LogMessage(logger.LogInfo, appname, "Removing kernel hooks...\n")
	kernel.StopCallbacks()

	// Stop all plugins
	logger.LogMessage(logger.LogInfo, appname, "Stopping plugins...\n")
	go example.PluginShutdown(&pluginSync)
	go classify.PluginShutdown(&pluginSync)
	go geoip.PluginShutdown(&pluginSync)
	go certcache.PluginShutdown(&pluginSync)
	go dns.PluginShutdown(&pluginSync)

	logger.LogMessage(logger.LogInfo, appname, "Waiting on plugins...\n")
	pluginSync.Wait()

	// Stop services
	logger.LogMessage(logger.LogInfo, appname, "Shutting down services...\n")
	exec.Shutdown()
	reports.Shutdown()
	settings.Shutdown()
	restd.Shutdown()
	conndict.Shutdown()
	dispatch.Shutdown()
	kernel.Shutdown()
	logger.Shutdown()
}

// Add signal handlers
func handleSignals() {
	ch := make(chan os.Signal)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-ch
		logger.LogMessage(logger.LogWarn, appname, "Received signal [%v]. Exiting...\n", sig)
		cleanup()
		os.Exit(1)
	}()
}

//update the netfilter queue rules for packetd
func updateRules() {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		logger.LogMessage(logger.LogErr, appname, "Error determining directory: %s\n", err.Error())
		return
	}
	exec.SystemCommand(dir+"/packetd_rules", []string{})
}

//remove the netfilter queue rules for packetd
func removeRules() {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		logger.LogMessage(logger.LogErr, appname, "Error determining directory: %s\n", err.Error())
		return
	}
	exec.SystemCommand(dir+"/packetd_rules", []string{"-r"})
}
