package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/c9s/goprocinfo/linux"
	"github.com/untangle/packetd/plugins/certfetch"
	"github.com/untangle/packetd/plugins/certsniff"
	"github.com/untangle/packetd/plugins/classify"
	"github.com/untangle/packetd/plugins/dns"
	"github.com/untangle/packetd/plugins/example"
	"github.com/untangle/packetd/plugins/geoip"
	"github.com/untangle/packetd/plugins/reporter"
	"github.com/untangle/packetd/plugins/revdns"
	"github.com/untangle/packetd/plugins/sni"
	"github.com/untangle/packetd/plugins/stats"
	"github.com/untangle/packetd/services/certcache"
	"github.com/untangle/packetd/services/dict"
	"github.com/untangle/packetd/services/dispatch"
	"github.com/untangle/packetd/services/kernel"
	"github.com/untangle/packetd/services/logger"
	"github.com/untangle/packetd/services/reports"
	"github.com/untangle/packetd/services/restd"
	"github.com/untangle/packetd/services/settings"
)

const rulesScript = "packetd_rules"

var memProfileTarget string
var cpuProfileTarget string
var localFlag bool
var cpuCount = getConcurrencyFactor()
var queueRange = getQueueRange()
var conntrackIntervalSeconds = 10

func main() {
	userinfo, err := user.Current()
	if err != nil {
		panic(err)
	}

	userid, err := strconv.Atoi(userinfo.Uid)
	if err != nil {
		panic(err)
	}

	if userid != 0 {
		panic("This application must be run as root!")
	}

	logger.Startup()
	parseArguments()

	// Start services
	startServices()

	handleSignals()

	// for i := 0; i < 5; i++ {
	// 	go func() {
	// 		logger.Info("Starting infinite loop...\n")
	// 		for {
	// 		}
	// 	}()
	// }

	if len(cpuProfileTarget) > 0 {
		startCPUProfiling()
	}

	// Start the plugins
	logger.Info("Starting plugins...\n")
	startPlugins()

	// Start the callbacks AFTER all services and plugins are initialized
	logger.Info("Starting kernel callbacks...\n")
	kernel.StartCallbacks(cpuCount, conntrackIntervalSeconds)

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

	if kernel.GetWarehouseFlag() == 'P' {
		dispatch.HandleWarehousePlayback()
	}

	if kernel.GetWarehouseFlag() == 'C' {
		kernel.StartWarehouseCapture()
	}

	// Wait until the shutdown flag is set
	for !kernel.GetShutdownFlag() {
		select {
		case <-kernel.GetShutdownChannel():
			logger.Info("Shutdown channel initiated... %v\n", kernel.GetShutdownFlag())
			break
		case <-time.After(1 * time.Hour):
			logger.Info(".\n")
			printStats()
		}
	}
	logger.Info("Shutdown initiated...\n")

	if kernel.GetWarehouseFlag() == 'C' {
		kernel.CloseWarehouseCapture()
	}

	// Stop kernel callbacks
	logger.Info("Removing kernel callbacks...\n")
	kernel.StopCallbacks()

	// Remove netfilter rules
	removeRules()

	// Stop all plugins
	logger.Info("Stopping plugins...\n")
	stopPlugins()

	// Stop services
	logger.Info("Stopping services...\n")

	if len(cpuProfileTarget) > 0 {
		stopCPUProfiling()
	}

	if len(memProfileTarget) > 0 {
		f, err := os.Create(memProfileTarget)
		if err == nil {
			runtime.GC()
			pprof.WriteHeapProfile(f)
			f.Close()
		}
	}

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
	debugPtr := flag.Bool("debug", false, "enable debug")
	bypassPtr := flag.Bool("bypass", false, "ignore live traffic")
	timestampPtr := flag.Bool("no-timestamp", false, "disable timestamp in logging")
	playbackFilePtr := flag.String("playback", "", "playback traffic from specified file")
	captureFilePtr := flag.String("capture", "", "capture traffic to specified file")
	playSpeedPtr := flag.Int("playspeed", 100, "traffic playback speed percentage")
	cpuProfilePtr := flag.String("cpuprofile", "", "write cpu profile to file")
	memProfilePtr := flag.String("memprofile", "", "write memory profile to file")
	logFilePtr := flag.String("logfile", "", "file to redirect stdout/stderr")
	cpuCountPtr := flag.Int("cpucount", cpuCount, "override the cpucount manually")

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

	if *debugPtr {
		kernel.SetDebugFlag()
	}

	if *bypassPtr {
		kernel.SetBypassFlag(1)
	}

	if *timestampPtr {
		logger.DisableTimestamp()
	}

	if len(*playbackFilePtr) != 0 {
		kernel.SetWarehouseFile(*playbackFilePtr)
		kernel.SetWarehouseFlag('P')
	}

	if len(*captureFilePtr) != 0 {
		kernel.SetWarehouseFile(*captureFilePtr)
		kernel.SetWarehouseFlag('C')
	}

	if *playSpeedPtr != 1 {
		kernel.SetWarehouseSpeed(*playSpeedPtr)
	}

	if *cpuProfilePtr != "" {
		cpuProfileTarget = *cpuProfilePtr
	}

	if cpuCountPtr != nil {
		cpuCount = *cpuCountPtr
	}

	if *memProfilePtr != "" {
		memProfileTarget = *memProfilePtr
	}

	if *logFilePtr != "" {
		logFile, err := os.OpenFile(*logFilePtr, os.O_WRONLY|os.O_CREATE|os.O_SYNC|os.O_TRUNC, 0755)
		if err != nil {
			panic("Failed to write to log file\n")
		}
		syscall.Dup2(int(logFile.Fd()), 1)
		syscall.Dup2(int(logFile.Fd()), 2)
	}

}

// startServices starts all the services
func startServices() {
	logger.Info("Starting services...\n")

	printVersion()
	loadRequirements()

	kernel.Startup()
	dispatch.Startup(conntrackIntervalSeconds)
	settings.Startup()
	reports.Startup()
	dict.Startup()
	restd.Startup()
	certcache.Startup()
}

// stopServices stops all the services
func stopServices() {
	c := make(chan bool)
	go func() {
		certcache.Shutdown()
		restd.Shutdown()
		dict.Shutdown()
		reports.Shutdown()
		settings.Shutdown()
		dispatch.Shutdown()
		kernel.Shutdown()
		logger.Shutdown()
		c <- true
	}()

	select {
	case <-c:
	case <-time.After(10 * time.Second):
		// can't use logger as it may be stopped
		fmt.Printf("ERROR: Failed to properly shutdown services\n")
		time.Sleep(1 * time.Second)
	}
}

// startPlugins starts all the plugins (in parallel)
func startPlugins() {
	var wg sync.WaitGroup

	// Start Plugins
	startups := []func(){
		example.PluginStartup,
		classify.PluginStartup,
		geoip.PluginStartup,
		certfetch.PluginStartup,
		certsniff.PluginStartup,
		dns.PluginStartup,
		revdns.PluginStartup,
		sni.PluginStartup,
		stats.PluginStartup,
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
		certfetch.PluginShutdown,
		certsniff.PluginShutdown,
		dns.PluginShutdown,
		revdns.PluginShutdown,
		sni.PluginShutdown,
		stats.PluginShutdown,
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
	// Add SIGINT & SIGTERM handler (exit)
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-ch
		go func() {
			logger.Warn("Received signal [%v]. Setting shutdown flag\n", sig)
			kernel.SetShutdownFlag()
		}()
	}()

	// Add SIGQUIT handler (dump thread stack trace)
	quitch := make(chan os.Signal, 1)
	signal.Notify(quitch, syscall.SIGQUIT)
	go func() {
		for {
			<-quitch
			go dumpStack()
		}
	}()
}

// insert the netfilter queue rules for packetd
func insertRules() {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		logger.Err("Error determining directory: %s\n", err.Error())
		return
	}
	home, ok := os.LookupEnv("PACKETD_HOME")
	if ok && home != "" {
		dir = home
	}
	output, err := exec.Command(dir+"/"+rulesScript, queueRange).CombinedOutput()
	if err != nil {
		logger.Warn("Error running %v: %v\n", rulesScript, err.Error())
		kernel.SetShutdownFlag()
	} else {
		for _, line := range strings.Split(string(output), "\n") {
			if line != "" {
				logger.Info("%s\n", line)
			}
		}
	}
}

// remove the netfilter queue rules for packetd
func removeRules() {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		logger.Err("Error determining directory: %s\n", err.Error())
		return
	}
	home, ok := os.LookupEnv("PACKETD_HOME")
	if ok && home != "" {
		dir = home
	}
	logger.Info("Removing netfilter rules...\n")
	err = exec.Command(dir+"/"+rulesScript, "-r", queueRange).Run()
	if err != nil {
		logger.Err("Failed to remove rules: %s\n", err.Error())
	}
	logger.Info("Removing netfilter rules...done\n")
}

// prints some basic stats about packetd
func printStats() {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	logger.Info("Memory Stats:\n")
	logger.Info("Memory Alloc: %d kB\n", (mem.Alloc / 1024))
	logger.Info("Memory TotalAlloc: %d kB\n", (mem.TotalAlloc / 1024))
	logger.Info("Memory HeapAlloc: %d kB\n", (mem.HeapAlloc / 1024))
	logger.Info("Memory HeapSys: %d kB\n", (mem.HeapSys / 1024))

	logger.Info("Reports EventsLogged: %d\n", reports.EventsLogged)
	stats, err := getProcStats()
	if err == nil {
		for _, line := range strings.Split(stats, "\n") {
			if line != "" {
				logger.Info("%s\n", line)
			}
		}
	} else {
		logger.Warn("Failed to read stats: %v\n", err)
	}
}

func getProcStats() (string, error) {
	file, err := os.OpenFile("/proc/"+strconv.Itoa(os.Getpid())+"/status", os.O_RDONLY, 0660)
	if err != nil {
		return "", err
	}

	defer file.Close()

	var interesting = ""
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		re, err := regexp.Compile("[[:space:]]+")
		if err != nil {
			return "", nil
		}
		line = re.ReplaceAllString(line, " ")

		if strings.HasPrefix(line, "Rss") {
			interesting += line + "\n"
		}
		if strings.HasPrefix(line, "Threads") {
			interesting += line + "\n"
		}
	}
	return interesting, nil
}

// getQueueRange gets the nfqueue specification
func getQueueRange() string {
	str := "2000"
	str = str + "-" + strconv.Itoa(2000+cpuCount)
	return str
}

// load all packetd requirements
func loadRequirements() {
	err := exec.Command("modprobe", "nf_conntrack").Run()
	if err != nil {
		logger.Err("Failed to modprobe nf_conntrack: %s", err.Error())
	}
	err = ioutil.WriteFile("/proc/sys/net/netfilter/nf_conntrack_acct", []byte("1"), 0644)
	if err != nil {
		logger.Err("Failed to enable nf_conntrack_acct %s", err.Error())
	}
}

// startCPUProfiling starts the CPU profiling processing
func startCPUProfiling() {
	f, err := os.Create(cpuProfileTarget)
	if err != nil {
		logger.Err("Could not create CPU profile: ", err)
	}
	if err := pprof.StartCPUProfile(f); err != nil {
		logger.Err("Could not start CPU profile: ", err)
	}

	logger.Info("pprof listening on localhost:6060\n")
	go func() {
		http.ListenAndServe("localhost:6060", nil)
	}()
}

// stopCPUProfiling stops the CPU profiling processing
func stopCPUProfiling() {
	pprof.StopCPUProfile()
}

// getConcurrencyFactor returns the number of CPUs
// or 4 if any error occurs in determining the number
func getConcurrencyFactor() int {
	cpuinfo, err := linux.ReadCPUInfo("/proc/cpuinfo")
	if err != nil {
		logger.Warn("Error reading cpuinfo: %s\n", err.Error())
		return 4
	}
	return cpuinfo.NumCore()
}

// dumpStack to /tmp/packetd.stack and log
func dumpStack() {
	buf := make([]byte, 1<<20)
	stacklen := runtime.Stack(buf, true)
	ioutil.WriteFile("/tmp/packetd.stack", buf[:stacklen], 0644)
	logger.Warn("Printing Thread Dump...\n")
	logger.Warn("\n\n%s\n\n", buf[:stacklen])
	logger.Warn("Thread dump complete.\n")
}
