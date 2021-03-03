package restd

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"os/exec"
	"reflect"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/untangle/packetd/services/appclassmanager"
	"github.com/untangle/packetd/services/certmanager"
	"github.com/untangle/packetd/services/dispatch"
	"github.com/untangle/packetd/services/kernel"
	"github.com/untangle/packetd/services/logger"
	"github.com/untangle/packetd/services/netspace"
	"github.com/untangle/packetd/services/overseer"
	"github.com/untangle/packetd/services/reports"
	"github.com/untangle/packetd/services/settings"
)

var engine *gin.Engine
var logsrc = "gin"

// Startup is called to start the rest daemon
func Startup() {

	gin.SetMode(gin.ReleaseMode)
	gin.DisableConsoleColor()
	gin.DefaultWriter = logger.NewLogWriter(logsrc)
	gin.DebugPrintRouteFunc = func(httpMethod, absolutePath, handlerName string, nuHandlers int) {
		logger.LogMessageSource(logger.LogLevelDebug, logsrc, "%v %v %v %v\n", httpMethod, absolutePath, handlerName, nuHandlers)
	}

	engine = gin.New()
	engine.Use(ginlogger())
	engine.Use(gin.Recovery())
	engine.Use(addHeaders)

	// Allow cross-site for dev - this should be disabled in production
	// config := cors.DefaultConfig()
	// config.AllowAllOrigins = true
	// engine.Use(cors.New(config))

	// A server-side store would be better IMO, but I can't find one.
	// -dmorris
	store := cookie.NewStore([]byte(GenerateRandomString(32)))
	// store := cookie.NewStore([]byte("secret"))

	engine.Use(sessions.Sessions("auth_session", store))
	engine.Use(addTokenToSession)

	engine.GET("/", rootHandler)

	engine.GET("/ping", pingHandler)

	engine.POST("/account/login", authRequired())
	engine.POST("/account/logout", authLogout)
	engine.GET("/account/logout", authLogout)
	engine.GET("/account/status", authStatus)

	api := engine.Group("/api")
	api.Use(authRequired())

	api.GET("/settings", getSettings)
	api.GET("/settings/*path", getSettings)
	api.POST("/settings", setSettings)
	api.POST("/settings/*path", setSettings)
	api.DELETE("/settings", trimSettings)
	api.DELETE("/settings/*path", trimSettings)

	api.GET("/logging/:logtype", getLogOutput)

	api.GET("/defaults", getDefaultSettings)
	api.GET("/defaults/*path", getDefaultSettings)

	api.POST("/reports/create_query", reportsCreateQuery)
	api.GET("/reports/get_data/:query_id", reportsGetData)
	api.POST("/reports/close_query/:query_id", reportsCloseQuery)

	api.POST("/warehouse/capture", warehouseCapture)
	api.POST("/warehouse/close", warehouseClose)
	api.POST("/warehouse/playback", warehousePlayback)
	api.POST("/warehouse/cleanup", warehouseCleanup)
	api.GET("/warehouse/status", warehouseStatus)
	api.POST("/control/traffic", trafficControl)

	api.POST("/netspace/request", netspaceRequest)
	api.POST("/netspace/check", netspaceCheck)

	api.GET("/status/sessions", statusSessions)
	api.GET("/status/system", statusSystem)
	api.GET("/status/hardware", statusHardware)
	api.GET("/status/upgrade", statusUpgradeAvailable)
	api.GET("/status/build", statusBuild)
	api.GET("/status/license", statusLicense)
	api.GET("/status/wantest/:device", statusWANTest)
	api.GET("/status/uid", statusUID)
	api.GET("/status/command/find_account", statusCommandFindAccount)
	api.GET("/status/interfaces/:device", statusInterfaces)
	api.GET("/status/arp/", statusArp)
	api.GET("/status/arp/:device", statusArp)
	api.GET("/status/dhcp", statusDHCP)
	api.GET("/status/route", statusRoute)
	api.GET("/status/routetables", statusRouteTables)
	api.GET("/status/route/:table", statusRoute)
	api.GET("/status/rules", statusRules)
	api.GET("/status/routerules", statusRouteRules)
	api.GET("/status/wwan/:device", statusWwan)
	api.GET("/status/wifichannels/:device", statusWifiChannels)
	api.GET("/status/wifimodelist/:device", statusWifiModelist)
	api.GET("/status/diagnostics", statusDiagnostics)

	api.GET("/threatprevention/lookup/:host", threatpreventionGetInfo)

	api.GET("/wireguard/keypair", wireguardKeyPair)
	api.POST("/wireguard/publickey", wireguardPublicKey)

	api.GET("/classify/applications", getClassifyAppTable)
	api.GET("/classify/categories", getClassifyCatTable)

	api.GET("/logger/:source", loggerHandler)
	api.GET("/debug", debugHandler)
	api.POST("/gc", gcHandler)

	api.POST("/fetch-licenses", fetchLicensesHandler)
	api.POST("/factory-reset", factoryResetHandler)
	api.POST("/sysupgrade", sysupgradeHandler)
	api.POST("/upgrade", upgradeHandler)

	api.POST("/reboot", rebootHandler)
	api.POST("/shutdown", shutdownHandler)

	api.POST("/releasedhcp/:device", releaseDhcp)
	api.POST("/renewdhcp/:device", renewDhcp)
	// files
	engine.Static("/admin", "/www/admin")
	engine.Static("/settings", "/www/settings")
	engine.Static("/reports", "/www/reports")
	engine.Static("/setup", "/www/setup")
	engine.Static("/static", "/www/static")
	// handle 404 routes
	engine.NoRoute(noRouteHandler)

	prof := engine.Group("/pprof")
	prof.Use(authRequired())

	prof.GET("/", pprofHandler(pprof.Index))
	prof.GET("/cmdline", pprofHandler(pprof.Cmdline))
	prof.GET("/profile", pprofHandler(pprof.Profile))
	prof.POST("/symbol", pprofHandler(pprof.Symbol))
	prof.GET("/symbol", pprofHandler(pprof.Symbol))
	prof.GET("/trace", pprofHandler(pprof.Trace))
	prof.GET("/block", pprofHandler(pprof.Handler("block").ServeHTTP))
	prof.GET("/goroutine", pprofHandler(pprof.Handler("goroutine").ServeHTTP))
	prof.GET("/heap", pprofHandler(pprof.Handler("heap").ServeHTTP))
	prof.GET("/mutex", pprofHandler(pprof.Handler("mutex").ServeHTTP))
	prof.GET("/threadcreate", pprofHandler(pprof.Handler("threadcreate").ServeHTTP))

	// listen and serve on 0.0.0.0:80
	go engine.Run(":80")

	cert, key := certmanager.GetConfiguredCert()
	go engine.RunTLS(":443", cert, key)

	logger.Info("The RestD engine has been started\n")
}

// Shutdown restd
func Shutdown() {
	return
}

// GenerateRandomString generates a random string of the specified length
func GenerateRandomString(n int) string {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		logger.Warn("Failed to generated secure key: %v\n", err)
		return "secret"
	}
	return base64.URLEncoding.EncodeToString(b)
}

// RemoveEmptyStrings removes and empty strings from the string slice and returns a new slice
func RemoveEmptyStrings(strings []string) []string {
	b := strings[:0]
	for _, x := range strings {
		if x != "" {
			b = append(b, x)
		}
	}
	return b
}

func rootHandler(c *gin.Context) {
	if isSetupWizardCompleted() {
		c.Redirect(http.StatusTemporaryRedirect, "/admin")
	} else {
		c.Redirect(http.StatusTemporaryRedirect, "/setup")
	}
}

// handles 404 routes
func noRouteHandler(c *gin.Context) {
	// MFW-704 - return 200 for JS map files requested by Safari on Mac
	if strings.Contains(c.Request.URL.Path, ".js.map") {
		c.String(http.StatusOK, "")
	}
	// otherwise browser will default to its 404 handler
}

func pingHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "pong",
	})
}

// loggerHandler handles getting and setting the log level for the different logger sources
func loggerHandler(c *gin.Context) {
	queryStr := c.Param("source")
	if queryStr == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "missing logger source"})
		return
	}

	// split passed query on equal character to get the function arguments
	info := strings.Split(queryStr, "=")

	// we expect either one or two arguments
	if len(info) < 1 || len(info) > 2 {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid logger syntax"})
	}

	// single argument is a level query
	if len(info) == 1 {
		level := logger.SearchSourceLogLevel(info[0])
		if level < 0 {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid log source specified"})
		} else {
			c.JSON(http.StatusOK, gin.H{
				"source": info[0],
				"level":  logger.FindLogLevelName(level),
			})
		}
		return
	}

	// two arguments is a request to adjust the level of a source so
	// start by finding the numeric level for the level name
	setlevel := logger.FindLogLevelValue(info[1])
	if setlevel < 0 {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid log level specified"})
		return
	}

	// set the level for the source
	nowlevel := logger.AdjustSourceLogLevel(info[0], setlevel)

	// return old and new values
	c.JSON(http.StatusOK, gin.H{
		"source":   info[0],
		"oldlevel": logger.FindLogLevelName(nowlevel),
		"newlevel": logger.FindLogLevelName(setlevel),
	})
}

func debugHandler(c *gin.Context) {
	var buffer *bytes.Buffer = new(bytes.Buffer)

	overseer.GenerateReport(buffer)
	buffer.WriteString("<BR><BR>\r\n")
	logger.GenerateReport(buffer)
	c.Data(http.StatusOK, "text/html; chareset=utf-8", buffer.Bytes())
}

func gcHandler(c *gin.Context) {
	logger.Info("Calling FreeOSMemory()...\n")
	debug.FreeOSMemory()
}

func pprofHandler(h http.HandlerFunc) gin.HandlerFunc {
	handler := http.HandlerFunc(h)
	return func(c *gin.Context) {
		handler.ServeHTTP(c.Writer, c.Request)
	}
}

func reportsGetData(c *gin.Context) {
	queryStr := c.Param("query_id")
	if queryStr == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "query_id not found"})
		return
	}
	queryID, err := strconv.ParseUint(queryStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}

	str, err := reports.GetData(queryID)
	if err != nil {
		//c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		// FIXME the UI pukes if you respond with 500 currently
		// once its fixed, we should change this back
		c.JSON(http.StatusOK, gin.H{"error": err})
		return
	}

	c.Header("Content-Type", "application/json")
	c.String(http.StatusOK, str)
	return
}

func reportsCreateQuery(c *gin.Context) {
	body, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	q, err := reports.CreateQuery(string(body))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	str := fmt.Sprintf("%v", q.ID)
	logger.Debug("CreateQuery(%s)\n", str)
	c.String(http.StatusOK, str)
}

func reportsCloseQuery(c *gin.Context) {
	queryStr := c.Param("query_id")
	if queryStr == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "query_id not found"})
		return
	}
	queryID, err := strconv.ParseUint(queryStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}

	str, err := reports.CloseQuery(queryID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}

	c.String(http.StatusOK, str)
	return
}

func warehousePlayback(c *gin.Context) {
	var data map[string]string
	var body []byte
	var filename string
	var speedstr string
	var speedval int
	var found bool
	var err error

	body, err = ioutil.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}

	err = json.Unmarshal(body, &data)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}

	filename, found = data["filename"]
	if found != true {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "filename not specified"})
		return
	}

	speedstr, found = data["speed"]
	if found == true {
		speedval, err = strconv.Atoi(speedstr)
		if err != nil {
			speedval = 1
		}
	} else {
		speedval = 1
	}

	kernel.SetWarehouseFlag('P')
	kernel.SetWarehouseFile(filename)
	kernel.SetWarehouseSpeed(speedval)

	logger.Info("Beginning playback of file:%s speed:%d\n", filename, speedval)
	dispatch.HandleWarehousePlayback()

	c.JSON(http.StatusOK, "Playback started")
}

func warehouseCleanup(c *gin.Context) {
	dispatch.HandleWarehouseCleanup()
	c.JSON(http.StatusOK, "Cleanup success\n")
}

func warehouseCapture(c *gin.Context) {

	var data map[string]string
	var body []byte
	var filename string
	var found bool
	var err error

	body, err = ioutil.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}

	err = json.Unmarshal(body, &data)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}

	filename, found = data["filename"]
	if found != true {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "filename not specified"})
		return
	}

	kernel.SetWarehouseFlag('C')
	kernel.SetWarehouseFile(filename)
	kernel.StartWarehouseCapture()

	logger.Info("Beginning capture to file:%s\n", filename)

	c.JSON(http.StatusOK, "Capture started")
}

func warehouseClose(c *gin.Context) {
	kernel.CloseWarehouseCapture()
	kernel.SetWarehouseFlag('I')

	c.JSON(http.StatusOK, "Capture finished\n")
}

func warehouseStatus(c *gin.Context) {
	var status string

	status = "UNKNOWN"
	flag := kernel.GetWarehouseFlag()
	switch flag {
	case 'I':
		status = "IDLE"
		break
	case 'P':
		status = "PLAYBACK"
		break
	case 'C':
		status = "CAPTURE"
		break
	}
	c.JSON(http.StatusOK, status)
}

func trafficControl(c *gin.Context) {
	var data map[string]string
	var body []byte
	var bypass string
	var found bool
	var err error

	body, err = ioutil.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}

	err = json.Unmarshal(body, &data)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}

	bypass, found = data["bypass"]
	if found == true {
		if strings.EqualFold(bypass, "TRUE") {
			logger.Info("Setting traffic bypass flag\n")
			kernel.SetBypassFlag(1)
			c.JSON(http.StatusOK, "Traffic bypass flag ENABLED")
		} else if strings.EqualFold(bypass, "FALSE") {
			logger.Info("Clearing traffic bypass flag\n")
			kernel.SetBypassFlag(0)
			c.JSON(http.StatusOK, "Traffic bypass flag CLEARED")
		} else {
			c.JSON(http.StatusOK, gin.H{"error": "Parameter must be TRUE or FALSE"})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"error": "Invalid or missing traffic control command"})
}

func getSettings(c *gin.Context) {
	var segments []string

	path := c.Param("path")

	if path == "" {
		segments = nil
	} else {
		segments = RemoveEmptyStrings(strings.Split(path, "/"))
	}

	jsonResult, err := settings.GetSettings(segments)
	if err != nil {
		c.JSON(http.StatusInternalServerError, jsonResult)
	} else {
		c.JSON(http.StatusOK, jsonResult)
	}
	return
}

func getDefaultSettings(c *gin.Context) {
	var segments []string

	path := c.Param("path")

	if path == "" {
		segments = nil
	} else {
		segments = RemoveEmptyStrings(strings.Split(path, "/"))
	}

	jsonResult, err := settings.GetDefaultSettings(segments)
	if err != nil {
		c.JSON(http.StatusInternalServerError, jsonResult)
	} else {
		c.JSON(http.StatusOK, jsonResult)
	}
	return
}

// getLogOutput will take a logtype param (ie: dmesg, logread, syslog) and attempt to retrieve the log output for that logtype, or default to logread
func getLogOutput(c *gin.Context) {

	var logcmd string

	switch logtype := c.Param("logtype"); logtype {
	case "dmesg":
		logcmd = "/bin/dmesg"
	case "syslog":
		logcmd = "cat /var/log/syslog"
	default:
		logcmd = "/sbin/logread"
	}

	output, err := exec.Command(logcmd).CombinedOutput()

	if err != nil {
		logger.Err("Error getting log output from %s: %v\n", logcmd, string(output))
		c.JSON(http.StatusInternalServerError, gin.H{"error": string(output)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"logresults": output})
	return
}

func getClassifyAppTable(c *gin.Context) {
	appTable, err := appclassmanager.GetApplicationTable()

	if err != nil {
		logger.Warn("Unable to get classd application table: %s \n", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.Header("Content-Type", "application/json")
	c.String(http.StatusOK, appTable)
	return
}

func getClassifyCatTable(c *gin.Context) {
	catTable, err := appclassmanager.GetCategoryTable()

	if err != nil {
		logger.Warn("Unable to get classd category table: %s \n", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.Header("Content-Type", "application/json")
	c.String(http.StatusOK, catTable)
	return
}

func setSettings(c *gin.Context) {
	var segments []string
	path := c.Param("path")
	force := c.Query("force")
	forceSync := false

	if path == "" {
		segments = nil
	} else {
		segments = RemoveEmptyStrings(strings.Split(path, "/"))
	}

	body, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}

	var bodyJSONObject interface{}
	err = json.Unmarshal(body, &bodyJSONObject)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
	}

	if force != "" {
		var parseErr error
		forceSync, parseErr = strconv.ParseBool(force)

		if parseErr != nil {
			forceSync = false
		}
	}
	jsonResult, err := settings.SetSettings(segments, bodyJSONObject, forceSync)
	if err != nil {
		c.JSON(http.StatusInternalServerError, jsonResult)
	} else {
		c.JSON(http.StatusOK, jsonResult)
	}
	return
}

func trimSettings(c *gin.Context) {
	var segments []string
	path := c.Param("path")

	if path == "" {
		segments = nil
	} else {
		segments = RemoveEmptyStrings(strings.Split(path, "/"))
	}

	jsonResult, err := settings.TrimSettings(segments)
	if err != nil {
		c.JSON(http.StatusInternalServerError, jsonResult)
	} else {
		c.JSON(http.StatusOK, jsonResult)
	}
	return
}

func addHeaders(c *gin.Context) {
	c.Header("Cache-Control", "must-revalidate")
	// c.Header("Example-Header", "foo")
	// c.Header("Access-Control-Allow-Origin", "*")
	// c.Header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE")
	// c.Header("Access-Control-Allow-Headers", "X-Custom-Header")
	c.Next()
}

// addTokenToSession checks for a "token" argument, and adds it to the session
// this is easier than passing it around among redirects
func addTokenToSession(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		return
	}
	logger.Info("Saving token in session: %v\n", token)
	session := sessions.Default(c)
	session.Set("token", token)
	err := session.Save()
	if err != nil {
		logger.Warn("Error saving session: %s\n", err.Error())
	}
	authRequired()
}

// returns true if the setup wizard is completed, or false if not
// if any error occurs it returns true (assumes the wizard is completed)
func isSetupWizardCompleted() bool {
	wizardCompletedJSON, err := settings.GetSettings([]string{"system", "setupWizard", "completed"})
	if err != nil {
		logger.Warn("Failed to read setup wizard completed settings: %v\n", err.Error())
		return true
	}
	if wizardCompletedJSON == nil {
		logger.Warn("Failed to read setup wizard completed settings: %v\n", wizardCompletedJSON)
		return true
	}
	wizardCompletedBool, ok := wizardCompletedJSON.(bool)
	if !ok {
		logger.Warn("Invalid type of setup wizard completed setting: %v %v\n", wizardCompletedJSON, reflect.TypeOf(wizardCompletedJSON))
		return true
	}

	return wizardCompletedBool
}

func ginlogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.LogMessageSource(logger.LogLevelDebug, logsrc, "%v %v\n", c.Request.Method, c.Request.RequestURI)
		c.Next()
	}
}

func fetchLicensesHandler(c *gin.Context) {
	err := exec.Command("/usr/bin/fetch-licenses.sh").Run()
	if err != nil {
		logger.Warn("license fetch failed: %s\n", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch license"})
		return
	}

	logger.Notice("Fetch licenses... done\n")
	c.JSON(http.StatusOK, gin.H{"success": true})
	return
}

func factoryResetHandler(c *gin.Context) {
	outraw, err := exec.Command("/usr/bin/sync-settings", "-o", "openwrt", "-c").CombinedOutput()
	output := string(outraw)
	if err != nil {
		logger.Warn("sync-settings failed: %s (%s)\n", err.Error(), output)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to restory factory default settings"})
		return
	}

	logger.Notice("Factory reset... done\n")
	c.JSON(http.StatusOK, gin.H{"success": true})
	return
}

func sysupgradeHandler(c *gin.Context) {
	filename := "/tmp/sysupgrade.img"
	var output []byte

	file, _, err := c.Request.FormFile("file")
	if err != nil {
		logger.Warn("Failed to upload file: %s\n", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to upload image"})
		return
	}

	out, err := os.Create(filename)
	if err != nil {
		logger.Warn("Failed to create %s: %s\n", filename, err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to upload image"})
		return
	}

	_, err = io.Copy(out, file)
	out.Close()
	if err != nil {
		logger.Warn("Failed to upload image: %s\n", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to upload image"})
		return
	}

	logger.Notice("Checking sysupgrade file...\n")

	output, err = exec.Command("/sbin/sysupgrade", "-T", filename).Output()
	if err != nil {
		if strings.Contains(string(output), "not supported by this image") ||
			strings.Contains(string(output), "Use sysupgrade -F") {

			logger.Err("sysupgrade -T failed: %s\n", output)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Incompatible upgrade image"})
			return
		}
	}

	logger.Notice("Launching sysupgrade...\n")

	err = exec.Command("/sbin/sysupgrade", filename).Run()
	if err != nil {
		logger.Warn("sysupgrade failed: %s\n", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Upgrade failed"})
		return
	}
	logger.Notice("Launching sysupgrade... done\n")

	c.JSON(http.StatusOK, gin.H{"success": true})
	return
}

func upgradeHandler(c *gin.Context) {
	err := exec.Command("/usr/bin/upgrade.sh").Run()
	if err != nil {
		logger.Warn("upgrade failed: %s\n", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	logger.Notice("Launching upgrade... done\n")

	c.JSON(http.StatusOK, gin.H{"success": true})
	return
}

func releaseDhcp(c *gin.Context) {
	deviceName := c.Param("device")

	logger.Info("Releasing DHCP for device %s...\n", deviceName)

	// var/run/udhcpc-deviceName stores the PID of the DHCP client process with udhcpc on openwrt
	udhdpcFile, err := ioutil.ReadFile(fmt.Sprintf("/var/run/udhcpc-%s.pid", deviceName))

	if err != nil {
		// if we cannot find the udhcpc, then this probably isn't an openwrt device
		logger.Warn("Unable to get udhcpc pid: %v - Trying dhclient \n", err)
		err = exec.Command("dhclient", "-r", deviceName).Run()
		if err != nil {
			logger.Warn("Release DHCP with dhclient has failed: %s\n", err.Error())
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	} else {
		// Some parsing errors fail due to markup in the udhcpc file, so split it on new lines and take the first line
		udhcpcPid := strings.Split(string(udhdpcFile), "\n")[0]
		err = exec.Command("/bin/kill", "-SIGUSR2", udhcpcPid).Run()
		if err != nil {
			logger.Warn("Release DHCP by kill -sigusr2 %s has failed: %s\n", udhcpcPid, err.Error())

			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"success": true})
	return
}

func renewDhcp(c *gin.Context) {
	deviceName := c.Param("device")

	logger.Info("Renewing DHCP for device %s...\n", deviceName)

	// var/run/udhcpc-deviceName stores the PID of the DHCP client process with udhcpc on openwrt
	udhdpcFile, err := ioutil.ReadFile(fmt.Sprintf("/var/run/udhcpc-%s.pid", deviceName))

	if err != nil {
		// if we cannot find the udhcpc, then this probably isn't an openwrt device
		logger.Warn("Unable to get udhcpc pid: %v - Trying dhclient \n", err)
		err = exec.Command("dhclient", deviceName).Run()
		if err != nil {
			logger.Warn("Renew DHCP with dhclient has failed: %s\n", err.Error())
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	} else {
		// Some parsing errors fail due to markup in the udhcpc file, so split it on new lines and take the first line
		udhcpcPid := strings.Split(string(udhdpcFile), "\n")[0]
		// if we have the PID and no error then try to kill the SIGUSR1 PID (renews IP)
		err := exec.Command("/bin/kill", "-SIGUSR1", string(udhcpcPid)).Run()
		if err != nil {
			logger.Warn("Renew DHCP by killing PID sigusr1 has failed: %s\n", err.Error())
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"success": true})
	return
}

// Create WireGuard private and public keys and return in JSON object
func wireguardKeyPair(c *gin.Context) {
	var privateKey string
	var publicKey string
	var out []byte
	var err error
	var cmd *exec.Cmd
	var sin io.WriteCloser

	// first generate a private key
	cmd = exec.Command("/usr/bin/wg", "genkey")
	out, err = cmd.Output()

	if err != nil {
		logger.Err("Error generating private key: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": string(out)})
		return
	}

	// generate the public key for the private key
	privateKey = strings.TrimRight(string(out), "\r\n")
	cmd = exec.Command("/usr/bin/wg", "pubkey")
	sin, err = cmd.StdinPipe()

	// use a goroutine to write the private key to stdin because the
	// wg utility will not return until stdin is closed
	go func() {
		defer sin.Close()
		io.WriteString(sin, privateKey)
	}()

	out, err = cmd.Output()

	if err != nil {
		logger.Err("Error generating public key: %v\n", string(out))
		c.JSON(http.StatusInternalServerError, gin.H{"error": string(out)})
		return
	}

	publicKey = strings.TrimRight(string(out), "\r\n")

	// return the private and public keys to the caller
	c.JSON(http.StatusOK, gin.H{
		"privateKey": privateKey,
		"publicKey":  publicKey,
	})

	return
}

// Create WireGuard public key and return both in JSON object
func wireguardPublicKey(c *gin.Context) {
	var privateKey string
	var publicKey string
	var out []byte
	var cmd *exec.Cmd
	var sin io.WriteCloser

	var data map[string]string
	var body []byte
	var found bool
	var err error

	body, err = ioutil.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err})
		return
	}

	err = json.Unmarshal(body, &data)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err})
		return
	}

	privateKey, found = data["privateKey"]
	if found != true {
		c.JSON(http.StatusOK, gin.H{"error": "privateKey not specified"})
		return
	}

	// generate the public key for the private key
	cmd = exec.Command("/usr/bin/wg", "pubkey")
	sin, err = cmd.StdinPipe()

	// use a goroutine to write the private key to stdin because the
	// wg utility will not return until stdin is closed
	go func() {
		defer sin.Close()
		io.WriteString(sin, privateKey)
	}()

	out, err = cmd.Output()

	if err != nil {
		logger.Err("Error generating public key: %v\n", string(out))
		c.JSON(http.StatusInternalServerError, gin.H{"error": string(out)})
		return
	}

	publicKey = strings.TrimRight(string(out), "\r\n")

	// return the private and public keys to the caller
	c.JSON(http.StatusOK, gin.H{
		"privateKey": privateKey,
		"publicKey":  publicKey,
	})

	return
}

// called to request an unused network address block
func netspaceRequest(c *gin.Context) {
	var data map[string]string
	var body []byte
	var rawdata string
	var ipVersion int
	var hostID int
	var networkSize int
	var found bool
	var err error

	body, err = ioutil.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err})
		return
	}

	err = json.Unmarshal(body, &data)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err})
		return
	}

	rawdata, found = data["ipVersion"]
	if found != true {
		c.JSON(http.StatusOK, gin.H{"error": "ipVersion not specified"})
		return
	}

	ipVersion, err = strconv.Atoi(rawdata)
	if err != nil {
		ipVersion = 4
	}

	rawdata, found = data["hostID"]
	if found != true {
		c.JSON(http.StatusOK, gin.H{"error": "hostID not specified"})
		return
	}

	hostID, err = strconv.Atoi(rawdata)
	if err != nil {
		hostID = 1
	}

	rawdata, found = data["networkSize"]
	if found != true {
		c.JSON(http.StatusOK, gin.H{"error": "networkSize not specified"})
		return
	}

	networkSize, err = strconv.Atoi(rawdata)
	if err != nil {
		networkSize = 24
	}

	network := netspace.GetAvailableAddressSpace(ipVersion, hostID, networkSize)
	if network == nil {
		c.JSON(http.StatusOK, gin.H{"error": "unable to find an unused network"})
		return
	}

	addr := network.IP.String()
	size, _ := network.Mask.Size()
	cidr := fmt.Sprintf("%s/%d", addr, size)

	c.JSON(http.StatusOK, gin.H{
		"network": addr,
		"netsize": size,
		"cidr":    cidr,
	})
}

// called to see if an address conflicts with any registered network space
func netspaceCheck(c *gin.Context) {
	var data map[string]string
	var body []byte
	var rawdata string
	var found bool
	var err error

	body, err = ioutil.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err})
		return
	}

	err = json.Unmarshal(body, &data)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err})
		return
	}

	rawdata, found = data["cidr"]
	if found != true {
		c.JSON(http.StatusOK, gin.H{"error": "cidr not specified"})
		return
	}

	_, netobj, err := net.ParseCIDR(rawdata)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err.Error()})
		return
	}

	// pass empty owner since we want to check for conflicts with all netspace registrations
	network := netspace.IsNetworkAvailableNet("", *netobj)

	if network == nil {
		c.JSON(http.StatusOK, gin.H{"success": true})
		return
	}

	problem := "Address conflict with " + network.OwnerName + "/" + network.OwnerPurpose
	c.JSON(http.StatusOK, gin.H{"error": problem})
}

// called when rebooting device
func rebootHandler(c *gin.Context) {
	err := exec.Command("reboot").Run()
	if err != nil {
		logger.Warn("Failed to reboot system: %s\n", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
	return
}

// called when shutdown device
func shutdownHandler(c *gin.Context) {
	err := exec.Command("halt").Run()
	if err != nil {
		logger.Warn("Failed to shutdown system: %s\n", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
	return
}
