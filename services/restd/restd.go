package restd

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/pprof"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"strings"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/untangle/packetd/services/dispatch"
	"github.com/untangle/packetd/services/kernel"
	"github.com/untangle/packetd/services/logger"
	"github.com/untangle/packetd/services/overseer"
	"github.com/untangle/packetd/services/reports"
	"github.com/untangle/packetd/services/settings"
)

var engine *gin.Engine

// Startup is called to start the rest daemon
func Startup() {

	gin.SetMode(gin.ReleaseMode)
	gin.DisableConsoleColor()
	gin.DefaultWriter = logger.NewLogWriter()
	gin.DebugPrintRouteFunc = func(httpMethod, absolutePath, handlerName string, nuHandlers int) {
		logger.Info("GIN: %v %v %v %v\n", httpMethod, absolutePath, handlerName, nuHandlers)
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

	engine.GET("/", rootHandler)

	engine.GET("/ping", pingHandler)
	engine.GET("/debug", debugHandler)

	engine.POST("/account/login", authLogin)
	//engine.GET("/account/login", authLogin)
	engine.POST("/account/logout", authLogout)
	engine.GET("/account/logout", authLogout)
	engine.GET("/account/status", authStatus)

	api := engine.Group("/api")
	api.Use(authRequired(engine))

	api.GET("/settings", getSettings)
	api.GET("/settings/*path", getSettings)
	api.POST("/settings", setSettings)
	api.POST("/settings/*path", setSettings)
	api.DELETE("/settings", trimSettings)
	api.DELETE("/settings/*path", trimSettings)

	api.GET("/defaults", getDefaultSettings)
	api.GET("/defaults/*path", getDefaultSettings)

	api.POST("/reports/create_query", reportsCreateQuery)
	api.GET("/reports/get_data/:query_id", reportsGetData)
	api.POST("/reports/close_query/:query_id", reportsCloseQuery)

	api.POST("/warehouse/capture", warehouseCapture)
	api.POST("/warehouse/playback", warehousePlayback)
	api.POST("/warehouse/cleanup", warehouseCleanup)
	api.GET("/warehouse/status", warehouseStatus)
	api.POST("/control/traffic", trafficControl)

	api.GET("/status/sessions", statusSessions)
	api.GET("/status/system", statusSystem)
	api.GET("/status/hardware", statusHardware)

	api.POST("/sysupgrade", sysupgradeHandler)

	// files
	engine.Static("/admin", "/www/admin")
	engine.Static("/settings", "/www/settings")
	engine.Static("/reports", "/www/reports")
	engine.Static("/setup", "/www/setup")
	engine.Static("/static", "/www/static")

	prof := engine.Group("/pprof")
	prof.Use(authRequired(engine))

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
		logger.Info("Failed to generated secure key: %v\n", err)
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

func pingHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "pong",
	})
}

func debugHandler(c *gin.Context) {
	var buffer bytes.Buffer
	buffer = overseer.GenerateReport()
	c.Data(http.StatusOK, "text/html; chareset=utf-8", buffer.Bytes())
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

func warehouseCapture(c *gin.Context) {
	// FIXME - some day
	c.JSON(http.StatusOK, "THIS FUNCTION IS NOT YET IMPLEMENTED")
}

func warehouseCleanup(c *gin.Context) {
	dispatch.HandleWarehouseCleanup()
	c.JSON(http.StatusOK, "Cleanup success\n")
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

func setSettings(c *gin.Context) {
	var segments []string
	path := c.Param("path")

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

	jsonResult, err := settings.SetSettings(segments, bodyJSONObject)
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
		logger.Info("GIN: %v %v\n", c.Request.Method, c.Request.RequestURI)
		c.Next()
	}
}

func sysupgradeHandler(c *gin.Context) {
	filename := "/tmp/sysupgrade.img"

	file, _, err := c.Request.FormFile("file")
	if err != nil {
		logger.Warn("Failed to upload file: %s\n", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	out, err := os.Create(filename)
	if err != nil {
		logger.Warn("Failed to create %s: %s\n", filename, err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	_, err = io.Copy(out, file)
	out.Close()
	if err != nil {
		logger.Warn("Failed to upload image: %s\n", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	logger.Info("Launching sysupgrade...\n")

	err = exec.Command("/sbin/sysupgrade", filename).Run()
	if err != nil {
		logger.Warn("sysupgrade failed: %s\n", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	logger.Info("Launching sysupgrade... done\n")

	c.JSON(http.StatusOK, gin.H{"success": true})
	return
}
