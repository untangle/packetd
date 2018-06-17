package main

import (
	"flag"
	"github.com/untangle/packetd/plugins/certcache"
	"github.com/untangle/packetd/plugins/classify"
	"github.com/untangle/packetd/plugins/dns"
	"github.com/untangle/packetd/plugins/example"
	"github.com/untangle/packetd/plugins/geoip"
	"github.com/untangle/packetd/services/conndict"
	"github.com/untangle/packetd/services/kernel"
	"github.com/untangle/packetd/services/reports"
	"github.com/untangle/packetd/services/restd"
	"github.com/untangle/packetd/services/settings"
	"github.com/untangle/packetd/services/support"
	"log"
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

	// Call Kernel API Startup
	kernel.Startup()

	// Set system logger to use our logger
	log.SetOutput(support.NewLogWriter("log"))

	// Load the conndict module
	support.SystemCommand("modprobe", []string{"nf_conntrack_dict"})

	// Start services
	support.Startup()
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

	support.LogMessage(support.LogInfo, appname, "Untangle Packet Daemon Version %s\n", "1.00")

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
		support.LogMessage(support.LogInfo, appname, ".\n")
	}
}

// Cleanup packetd and exit
func cleanup() {
	// Prevent further calls
	exitLock.Lock()

	// Remove netfilter rules
	support.LogMessage(support.LogInfo, appname, "Removing netfilter rules...\n")
	removeRules()

	// Stop kernel callbacks
	support.LogMessage(support.LogInfo, appname, "Removing kernel hooks...\n")
	kernel.StopCallbacks()

	// Stop all plugins
	support.LogMessage(support.LogInfo, appname, "Stopping plugins...\n")
	go example.PluginShutdown(&pluginSync)
	go classify.PluginShutdown(&pluginSync)
	go geoip.PluginShutdown(&pluginSync)
	go certcache.PluginShutdown(&pluginSync)
	go dns.PluginShutdown(&pluginSync)

	support.LogMessage(support.LogInfo, appname, "Waiting on plugins...\n")
	pluginSync.Wait()

	// Stop services
	support.LogMessage(support.LogInfo, appname, "Shutting down services...\n")
	support.Shutdown()
	reports.Shutdown()
	settings.Shutdown()
	restd.Shutdown()
	conndict.Shutdown()

	// Call Kernel cleanup
	kernel.Shutdown()
}

// Add signal handlers
func handleSignals() {
	ch := make(chan os.Signal)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	signal.Notify(ch, os.Interrupt, syscall.SIGINT)
	go func() {
		<-ch
		support.LogMessage(support.LogInfo, appname, "Received signal. Exiting...\n")
		cleanup()
		os.Exit(1)
	}()
}

//update the netfilter queue rules for packetd
func updateRules() {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		support.LogMessage(support.LogErr, appname, "Error determining directory: %s\n", err.Error())
		return
	}
	support.SystemCommand(dir+"/packetd_rules", []string{})
}

//remove the netfilter queue rules for packetd
func removeRules() {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		support.LogMessage(support.LogErr, appname, "Error determining directory: %s\n", err.Error())
		return
	}
	support.SystemCommand(dir+"/packetd_rules", []string{"-r"})
}
