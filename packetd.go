package main

import (
	"flag"
	"github.com/untangle/packetd/plugins/certcache"
	"github.com/untangle/packetd/plugins/classify"
	"github.com/untangle/packetd/plugins/dns"
	"github.com/untangle/packetd/plugins/example"
	"github.com/untangle/packetd/plugins/geoip"
	"github.com/untangle/packetd/plugins/reporter"
	"github.com/untangle/packetd/plugins/sni"
	"github.com/untangle/packetd/services/dict"
	"github.com/untangle/packetd/services/dispatch"
	"github.com/untangle/packetd/services/kernel"
	"github.com/untangle/packetd/services/logger"
	"github.com/untangle/packetd/services/reports"
	"github.com/untangle/packetd/services/restd"
	"github.com/untangle/packetd/services/settings"
	"github.com/untangle/packetd/services/syscmd"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"
)

var exitLock sync.Mutex

func main() {
	handleSignals()
	parseArguments()

	// Start services
	logger.Startup()
	printVersion()
	kernel.Startup()
	dispatch.Startup()
	syscmd.Startup()
	settings.Startup()
	reports.Startup()
	dict.Startup()

	// Start all the callbacks
	kernel.StartCallbacks()

	// Start the plugins
	startPlugins()

	// Start REST HTTP daemon
	go restd.Startup()

	// Insert netfilter rules
	updateRules()

	// Check that all the C services started correctly
	// This flag is only set on Startup so this only needs to be checked once
	time.Sleep(1)
	if kernel.GetShutdownFlag() != 0 {
		cleanup()
		os.Exit(0)
	}

	// Loop forever
	for {
		time.Sleep(600 * time.Second)
		logger.Info(".\n")

		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)
		logger.Debug("Memory Stats:\n")
		logger.Debug("Memory Alloc: %d\n", mem.Alloc)
		logger.Debug("Memory TotalAlloc: %d\n", mem.TotalAlloc)
		logger.Debug("Memory HeapAlloc: %d\n", mem.HeapAlloc)
		logger.Debug("Memory HeapSys: %d\n", mem.HeapSys)
	}
}

func printVersion() {
	logger.Info("Untangle Packet Daemon Version %s\n", Version)
}

// parseArguments parses the command line arguments
func parseArguments() {
	classdAddressStringPtr := flag.String("classd", "127.0.0.1:8123", "host:port for classd daemon")
	disableConndictPtr := flag.Bool("disable-dict", false, "disable dict")
	versionPtr := flag.Bool("version", false, "version")

	flag.Parse()

	if *versionPtr {
		printVersion()
		os.Exit(0)
	}

	classify.SetHostPort(*classdAddressStringPtr)
	if *disableConndictPtr {
		dict.Disable()
	}
}

// Cleanup packetd and exit
func cleanup() {
	// Prevent further calls
	exitLock.Lock()

	// Remove netfilter rules
	logger.Info("Removing netfilter rules...\n")
	removeRules()

	// Stop kernel callbacks
	logger.Info("Removing kernel hooks...\n")
	kernel.StopCallbacks()

	// Stop all plugins
	stopPlugins()

	// Stop services
	logger.Info("Shutting down services...\n")
	syscmd.Shutdown()
	reports.Shutdown()
	settings.Shutdown()
	restd.Shutdown()
	dict.Shutdown()
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
		sni.PluginStartup,
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
		sni.PluginShutdown,
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
		logger.Warn("Received signal [%v]. Exiting...\n", sig)
		cleanup()
		os.Exit(1)
	}()
}

// update the netfilter queue rules for packetd
func updateRules() {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		logger.Err("Error determining directory: %s\n", err.Error())
		return
	}
	syscmd.SystemCommand(dir+"/packetd_rules", []string{})
}

// remove the netfilter queue rules for packetd
func removeRules() {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		logger.Err("Error determining directory: %s\n", err.Error())
		return
	}
	syscmd.SystemCommand(dir+"/packetd_rules", []string{"-r"})
}
