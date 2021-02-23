package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
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
	"github.com/untangle/packetd/plugins/predicttraffic"
	"github.com/untangle/packetd/plugins/reporter"
	"github.com/untangle/packetd/plugins/revdns"
	"github.com/untangle/packetd/plugins/sni"
	"github.com/untangle/packetd/plugins/stats"
	"github.com/untangle/packetd/plugins/threatprevention"
	"github.com/untangle/packetd/services/appclassmanager"
	"github.com/untangle/packetd/services/certcache"
	"github.com/untangle/packetd/services/certmanager"
	"github.com/untangle/packetd/services/dict"
	"github.com/untangle/packetd/services/dispatch"
	"github.com/untangle/packetd/services/kernel"
	"github.com/untangle/packetd/services/logger"
	"github.com/untangle/packetd/services/netspace"
	"github.com/untangle/packetd/services/overseer"
	"github.com/untangle/packetd/services/predicttrafficsvc"
	"github.com/untangle/packetd/services/reports"
	"github.com/untangle/packetd/services/restd"
	"github.com/untangle/packetd/services/settings"
	"github.com/untangle/packetd/services/webroot"
)

const rulesScript = "packetd_rules"

var localFlag bool
var cpuProfileFilename = ""
var cpuCount = getConcurrencyFactor()
var queueStart = 2000
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

	if len(cpuProfileFilename) != 0 {
		cpu, err := os.Create(cpuProfileFilename)
		if err == nil {
			logger.Alert("+++++ CPU profiling is active. Output file:%s +++++\n", cpuProfileFilename)
			pprof.StartCPUProfile(cpu)
		} else {
			logger.Alert("+++++ Error creating file for CPU profile:%v ++++++\n", err)
			cpuProfileFilename = ""
		}
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

	if len(cpuProfileFilename) != 0 {
		pprof.StopCPUProfile()
		logger.Alert("+++++ CPU profiling is finished. Output file:%s  +++++\n", cpuProfileFilename)
	}

	logger.Info("Shutdown initiated...\n")

	if kernel.GetWarehouseFlag() == 'C' {
		kernel.CloseWarehouseCapture()
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
	disableDictPtr := flag.Bool("disable-dict", false, "disable dict")
	cpuProfilePtr := flag.String("cpuprofile", "", "filename for CPU pprof output")
	versionPtr := flag.Bool("version", false, "version")
	localPtr := flag.Bool("local", false, "run on console")
	bypassPtr := flag.Bool("bypass", false, "ignore live traffic")
	timestampPtr := flag.Bool("no-timestamp", false, "disable timestamp in logging")
	playbackFilePtr := flag.String("playback", "", "playback traffic from specified file")
	captureFilePtr := flag.String("capture", "", "capture traffic to specified file")
	playSpeedPtr := flag.Int("playspeed", 100, "traffic playback speed percentage")
	logFilePtr := flag.String("logfile", "", "file to redirect stdout/stderr")
	cpuCountPtr := flag.Int("cpucount", cpuCount, "override the cpucount manually")
	noNfqueuePtr := flag.Bool("no-nfqueue", false, "disable the nfqueue callback hook")
	noConntrackPtr := flag.Bool("no-conntrack", false, "disable the conntrack callback hook")
	noNetloggerPtr := flag.Bool("no-netlogger", false, "disable the netlogger callback hook")
	noCloudPtr := flag.Bool("no-cloud", false, "disable all cloud services")

	flag.Parse()

	classify.SetHostPort(*classdAddressStringPtr)

	if *disableDictPtr {
		dict.Disable()
	}

	if len(*cpuProfilePtr) > 0 {
		cpuProfileFilename = *cpuProfilePtr
	}

	if *versionPtr {
		printVersion()
		os.Exit(0)
	}

	if *localPtr {
		localFlag = true
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

	if cpuCountPtr != nil {
		cpuCount = *cpuCountPtr
	}

	if *logFilePtr != "" {
		logFile, err := os.OpenFile(*logFilePtr, os.O_WRONLY|os.O_CREATE|os.O_SYNC|os.O_TRUNC, 0755)
		if err != nil {
			panic("Failed to write to log file\n")
		}
		syscall.Dup3(int(logFile.Fd()), 1, 0)
		syscall.Dup3(int(logFile.Fd()), 2, 0)
	}

	if *noNfqueuePtr {
		kernel.FlagNoNfqueue = true
		logger.Alert("!!!!! The no-nfqueue flag was passed on the command line !!!!!\n")
	}

	if *noConntrackPtr {
		kernel.FlagNoConntrack = true
		logger.Alert("!!!!! The no-conntrack flag was passed on the command line !!!!!\n")
	}

	if *noNetloggerPtr {
		kernel.FlagNoNetlogger = true
		logger.Alert("!!!!! The no-netlogger flag was passed on the command line !!!!!\n")
	}

	if *noCloudPtr {
		kernel.FlagNoCloud = true
		logger.Alert("!!!!! The no-cloud flag was passed on the command line !!!!!\n")
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
	netspace.Startup()
	overseer.Startup()
	certmanager.Startup()
	appclassmanager.Startup()
	webroot.Startup()

	if !kernel.FlagNoCloud {
		predicttrafficsvc.Startup()
	}
}

// stopServices stops all the services
func stopServices() {
	c := make(chan bool)
	go func() {
		if !kernel.FlagNoCloud {
			predicttrafficsvc.Shutdown()
		}
		overseer.Shutdown()
		netspace.Shutdown()
		certmanager.Shutdown()
		appclassmanager.Shutdown()
		certcache.Shutdown()
		restd.Shutdown()
		dict.Shutdown()
		reports.Shutdown()
		settings.Shutdown()
		dispatch.Shutdown()
		kernel.Shutdown()
		webroot.Shutdown()
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
		threatprevention.PluginStartup,
		certfetch.PluginStartup,
		certsniff.PluginStartup,
		dns.PluginStartup,
		revdns.PluginStartup,
		sni.PluginStartup,
		stats.PluginStartup,
		reporter.PluginStartup}
	if !kernel.FlagNoCloud {
		startups = append(startups, predicttraffic.PluginStartup)
	}
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
		threatprevention.PluginShutdown,
		certfetch.PluginShutdown,
		certsniff.PluginShutdown,
		dns.PluginShutdown,
		revdns.PluginShutdown,
		sni.PluginShutdown,
		stats.PluginShutdown,
		reporter.PluginShutdown}
	if !kernel.FlagNoCloud {
		shutdowns = append(shutdowns, predicttraffic.PluginShutdown)
	}
	for _, f := range shutdowns {
		wg.Add(1)
		go func(f func()) {
			f()
			wg.Done()
		}(f)
	}

	wg.Wait()
}

// signalPlugins signals all plugins with a handler (in parallel)
func signalPlugins(message syscall.Signal) {
	var wg sync.WaitGroup

	targets := []func(syscall.Signal){
		stats.PluginSignal}
	for _, f := range targets {
		wg.Add(1)
		go func(f func(syscall.Signal)) {
			f(message)
			wg.Done()
		}(f)
	}

	wg.Wait()
}

// Add signal handlers
func handleSignals() {
	// Add SIGINT & SIGTERM handler (exit)
	termch := make(chan os.Signal, 1)
	signal.Notify(termch, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-termch
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
			sig := <-quitch
			logger.Info("Received signal [%v]. Calling dumpStack()\n", sig)
			go dumpStack()
		}
	}()

	// Add SIGHUP handler (call handlers)
	hupch := make(chan os.Signal, 1)
	signal.Notify(hupch, syscall.SIGHUP)
	go func() {
		for {
			sig := <-hupch
			logger.Info("Received signal [%v]. Calling handlers\n", sig)
			signalPlugins(syscall.SIGHUP)
		}
	}()
}

// insert the netfilter queue rules for packetd
func insertRules() {
	if kernel.FlagNoNfqueue {
		return
	}
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		logger.Err("Error determining directory: %s\n", err.Error())
		return
	}
	home, ok := os.LookupEnv("PACKETD_HOME")
	if ok && home != "" {
		dir = home
	}
	qmin := strconv.Itoa(queueStart)
	qmax := strconv.Itoa(queueStart + cpuCount - 1)
	output, err := exec.Command(dir+"/"+rulesScript, "INSERT", qmin, qmax).CombinedOutput()
	if err != nil {
		logger.Warn("Error running %v INSERT %v %v: %v\n", rulesScript, qmin, qmax, err.Error())
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
	output, err := exec.Command(dir+"/"+rulesScript, "REMOVE").CombinedOutput()
	if err != nil {
		logger.Err("Error running %v REMOVE: %v\n", err.Error())
	} else {
		for _, line := range strings.Split(string(output), "\n") {
			if line != "" {
				logger.Info("%s\n", line)
			}
		}
	}
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
	err = ioutil.WriteFile("/proc/sys/net/netfilter/nf_conntrack_timestamp", []byte("1"), 0644)
	if err != nil {
		logger.Err("Failed to enable nf_conntrack_timestamp %s", err.Error())
	}
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
