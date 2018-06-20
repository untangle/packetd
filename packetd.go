package main

import (
	"flag"
	"github.com/untangle/packetd/plugins/certcache"
	"github.com/untangle/packetd/plugins/classify"
	"github.com/untangle/packetd/plugins/dns"
	"github.com/untangle/packetd/plugins/example"
	"github.com/untangle/packetd/plugins/geoip"
	"github.com/untangle/packetd/plugins/reporter"
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

var logsrc = "packetd"
var exitLock sync.Mutex

func main() {
	handleSignals()
	parseArguments()

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

	// Start the plugins
	startPlugins()

	// Start REST HTTP daemon
	go restd.Startup()

	// Insert netfilter rules
	updateRules()

	// Startup Complete
	logger.LogMessage(logger.LogInfo, logsrc, "Untangle Packet Daemon Version %s\n", "1.00")

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
		logger.LogMessage(logger.LogInfo, logsrc, ".\n")
	}
}

// parseArguments parses the command line arguments
func parseArguments() {
	classdAddressStringPtr := flag.String("classd", "127.0.0.1:8123", "host:port for classd daemon")
	disableConndictPtr := flag.Bool("disable-conndict", false, "disable conndict")

	flag.Parse()

	classify.SetHostPort(*classdAddressStringPtr)
	if *disableConndictPtr {
		conndict.Disable()
	}
}

// Cleanup packetd and exit
func cleanup() {
	// Prevent further calls
	exitLock.Lock()

	// Remove netfilter rules
	logger.LogMessage(logger.LogInfo, logsrc, "Removing netfilter rules...\n")
	removeRules()

	// Stop kernel callbacks
	logger.LogMessage(logger.LogInfo, logsrc, "Removing kernel hooks...\n")
	kernel.StopCallbacks()

	// Stop all plugins
	stopPlugins()

	// Stop services
	logger.LogMessage(logger.LogInfo, logsrc, "Shutting down services...\n")
	exec.Shutdown()
	reports.Shutdown()
	settings.Shutdown()
	restd.Shutdown()
	conndict.Shutdown()
	dispatch.Shutdown()
	kernel.Shutdown()
	logger.Shutdown()
}

// startPlugins starts all the plugins (in parallel)
func startPlugins() {
	var wg sync.WaitGroup

	// Start Plugins
	startups := []func(){
		example.PluginStartup,
		classify.PluginStartup,
		geoip.PluginStartup,
		certcache.PluginStartup,
		dns.PluginStartup,
		reporter.PluginStartup}
	for _, f := range startups {
		wg.Add(1)
		go func(f func()) {
			f()
			wg.Done()
		}(f)
	}

	wg.Wait()
}

// stopPlugins stops all the plugins (in parallel)
func stopPlugins() {
	var wg sync.WaitGroup

	shutdowns := []func(){
		example.PluginShutdown,
		classify.PluginShutdown,
		geoip.PluginShutdown,
		certcache.PluginShutdown,
		dns.PluginShutdown,
		reporter.PluginShutdown}
	for _, f := range shutdowns {
		wg.Add(1)
		go func(f func()) {
			f()
			wg.Done()
		}(f)
	}

	wg.Wait()
}

// Add signal handlers
func handleSignals() {
	ch := make(chan os.Signal)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-ch
		logger.LogMessage(logger.LogWarn, logsrc, "Received signal [%v]. Exiting...\n", sig)
		cleanup()
		os.Exit(1)
	}()
}

//update the netfilter queue rules for packetd
func updateRules() {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		logger.LogMessage(logger.LogErr, logsrc, "Error determining directory: %s\n", err.Error())
		return
	}
	exec.SystemCommand(dir+"/packetd_rules", []string{})
}

//remove the netfilter queue rules for packetd
func removeRules() {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		logger.LogMessage(logger.LogErr, logsrc, "Error determining directory: %s\n", err.Error())
		return
	}
	exec.SystemCommand(dir+"/packetd_rules", []string{"-r"})
}
