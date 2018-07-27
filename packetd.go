package main

import (
	"bufio"
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

const rulesScript = "packetd_rules"
//const rulesScript = "packetd_rules_iptables" // FIXME - do not commit with this enabled
var localFlag bool

func main() {
	var lasttime int64

	handleSignals()
	parseArguments()

	// Start services
	logger.Info("Starting services...\n")
	startServices()

	// Start the plugins
	logger.Info("Starting plugins...\n")
	startPlugins()

	// Start the callbacks AFTER all services and plugins are initialized
	logger.Info("Starting kernel callbacks...\n")
	kernel.StartCallbacks()

	// Insert netfilter rules
	logger.Info("Inserting netfilter rules...\n")
	insertRules()

	// If the local flag is set we start a goroutine to watch for console input.
	// This can be used to quickly/easily tell the application to terminate when
	// running under gdb to diagnose threads hanging at shutdown. This requires
	// something other than CTRL+C since that is intercepted by gdb, and debugging
	// those kind of issues can be timing sensitive, so it's often not helpful to
	// figure out the PID and send a signal from another console.
	if localFlag {
		logger.Notice("Running on console - Press enter to terminate\n")
		go func() {
			reader := bufio.NewReader(os.Stdin)
			reader.ReadString('\n')
			logger.Notice("Console input detected - Application shutting down\n")
			kernel.SetShutdownFlag()
		}()
	}

	// Loop until the shutdown flag is set
	for kernel.GetShutdownFlag() == 0 {
		time.Sleep(time.Second)
		current := time.Now()

		if lasttime == 0 {
			lasttime = current.Unix()
		}

		if current.Unix() < (lasttime + 600) {
			continue
		}

		lasttime = current.Unix()
		logger.Info(".\n")

		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)
		logger.Debug("Memory Stats:\n")
		logger.Debug("Memory Alloc: %d\n", mem.Alloc)
		logger.Debug("Memory TotalAlloc: %d\n", mem.TotalAlloc)
		logger.Debug("Memory HeapAlloc: %d\n", mem.HeapAlloc)
		logger.Debug("Memory HeapSys: %d\n", mem.HeapSys)
	}

	// Remove netfilter rules
	logger.Info("Removing netfilter rules...\n")
	removeRules()

	// Stop kernel callbacks
	logger.Info("Removing kernel callbacks...\n")
	kernel.StopCallbacks()

	// Stop all plugins
	logger.Info("Stopping plugins...\n")
	stopPlugins()

	// Stop services
	logger.Info("Stopping services...\n")
	stopServices()
}

func printVersion() {
	logger.Info("Untangle Packet Daemon Version %s\n", Version)
}

// parseArguments parses the command line arguments
func parseArguments() {
	classdAddressStringPtr := flag.String("classd", "127.0.0.1:8123", "host:port for classd daemon")
	disableConndictPtr := flag.Bool("disable-dict", false, "disable dict")
	versionPtr := flag.Bool("version", false, "version")
	localPtr := flag.Bool("local", false, "run on console")

	flag.Parse()

	classify.SetHostPort(*classdAddressStringPtr)

	if *disableConndictPtr {
		dict.Disable()
	}

	if *versionPtr {
		printVersion()
		os.Exit(0)
	}

	if *localPtr {
		localFlag = true
	}
}

// startServices starts all the services
func startServices() {
	logger.Startup()
	printVersion()
	kernel.Startup()
	dispatch.Startup()
	syscmd.Startup()
	settings.Startup()
	reports.Startup()
	dict.Startup()
	restd.Startup()
}

// stopServices stops all the services
func stopServices() {
	restd.Shutdown()
	dict.Shutdown()
	reports.Shutdown()
	settings.Shutdown()
	syscmd.Shutdown()
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
		logger.Warn("Received signal [%v]. Setting shutdown flag\n", sig)
		kernel.SetShutdownFlag()
	}()
}

// insert the netfilter queue rules for packetd
func insertRules() {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		logger.Err("Error determining directory: %s\n", err.Error())
		return
	}
	syscmd.SystemCommand(dir+"/"+rulesScript, []string{})
}

// remove the netfilter queue rules for packetd
func removeRules() {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		logger.Err("Error determining directory: %s\n", err.Error())
		return
	}
	syscmd.SystemCommand(dir+"/"+rulesScript, []string{"-r"})
}
