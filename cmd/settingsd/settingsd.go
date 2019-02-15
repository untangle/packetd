package main

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/gin-contrib/location"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/contrib/static"
	"github.com/gin-gonic/gin"
	"github.com/untangle/packetd/services/logger"
	"github.com/untangle/packetd/services/restd"
	"github.com/untangle/packetd/services/settings"
)

var shutdownFlag = false
var engine *gin.Engine

func main() {
	var lasttime int64

	handleSignals()
	parseArguments()

	// Start services
	startServices()

	// Loop until the shutdown flag is set
	for shutdownFlag == false {
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

	// Stop services
	logger.Info("Stopping services...\n")
	stopServices()
}

// Startup is called to start the rest daemon
func startupRestDaemon() {
	gin.DisableConsoleColor()
	gin.DefaultWriter = logger.NewLogWriter()
	engine = gin.Default()
	store := cookie.NewStore([]byte(restd.GenerateRandomString(32)))
	engine.Use(sessions.Sessions("auth_session", store))
	engine.Use(location.Default())
	engine.MaxMultipartMemory = 8 << 22 // 32 MB

	engine.GET("/account/status", fakeAuthStatus)

	api := engine.Group("/api")
	api.GET("/settings", getSettings)
	api.GET("/settings/*path", getSettings)
	api.POST("/settings", setSettings)
	api.POST("/settings/*path", setSettings)
	api.DELETE("/settings", trimSettings)
	api.DELETE("/settings/*path", trimSettings)
	api.GET("/defaults", getDefaultSettings)
	api.GET("/defaults/*path", getDefaultSettings)

	// index
	engine.Use(static.Serve("/", static.LocalFile("/www", true)))

	// files
	engine.Static("/settings", "/www/settings")
	engine.Static("/static", "/www/static")

	// upload
	engine.POST("/upload", uploadFile)

	// listen and serve on 0.0.0.0:80
	go engine.Run(":80")

	logger.Info("The RestD engine has been started\n")
}

// parseArguments parses the command line arguments
func parseArguments() {
	return
}

// startServices starts all the services
func startServices() {
	logger.Startup()
	logger.Info("Starting services...\n")
	settings.Startup()
	startupRestDaemon()
}

// stopServices stops all the services
func stopServices() {
	c := make(chan bool)
	go func() {
		restd.Shutdown()
		settings.Shutdown()
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

// Add signal handlers
func handleSignals() {
	// Add SIGINT & SIGTERM handler (exit)
	ch := make(chan os.Signal)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-ch
		logger.Warn("Received signal [%v]. Setting shutdown flag\n", sig)
		shutdownFlag = true
	}()

	// Add SIGQUIT handler (dump thread stack trace)
	quitch := make(chan os.Signal, 1)
	signal.Notify(quitch, syscall.SIGQUIT)
	go func() {
		for {
			sig := <-quitch
			buf := make([]byte, 1<<20)
			logger.Warn("Received signal [%v]. Printing Thread Dump...\n", sig)
			stacklen := runtime.Stack(buf, true)
			logger.Warn("\n\n%s\n\n", buf[:stacklen])
			logger.Warn("Thread dump complete.\n")
		}
	}()
}

func splitter(r rune) bool {
	return r == ':' || r == '.'
}

func getSettings(c *gin.Context) {
	var segments []string

	path := c.Param("path")
	if path == "" {
		segments = nil
	} else {
		segments = restd.RemoveEmptyStrings(strings.Split(path, "/"))
	}

	shaStr, _ := c.GetQuery("sha1")
	if shaStr == "" {
		url := location.Get(c)
		if url != nil {
			parts := strings.FieldsFunc(url.Host, splitter)
			if len(parts) > 0 && len(parts[0]) == 40 {
				shaStr = parts[0]
			}
		}
	}
	if shaStr == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "No settings file (SHA1) specified"})
		return
	}
	if !validSha(shaStr) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid SHA1"})
	}

	jsonResult := settings.GetSettingsFile(segments, "/var/lib/settingsd/"+shaStr+".json")
	c.JSON(http.StatusOK, jsonResult)
	return
}

func getDefaultSettings(c *gin.Context) {
	var segments []string

	path := c.Param("path")

	if path == "" {
		segments = nil
	} else {
		segments = restd.RemoveEmptyStrings(strings.Split(path, "/"))
	}

	jsonResult := settings.GetDefaultSettings(segments)
	c.JSON(http.StatusOK, jsonResult)
	return
}

func setSettings(c *gin.Context) {
	c.JSON(http.StatusOK, map[string]interface{}{"result": "OK"})
}

func trimSettings(c *gin.Context) {
	c.JSON(http.StatusOK, map[string]interface{}{"result": "OK"})
	return
}

func uploadFile(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("File missing: %s", err.Error())})
		return
	}

	filename := tmpFileName("upload-", ".json")

	if err := c.SaveUploadedFile(file, filename); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Save error: %s", err.Error())})
		return
	}

	shaStr, err := fileSha1(filename)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Error computing SHA1: %s", err.Error())})
		return
	}

	if !validSha(shaStr) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid SHA1"})
		return
	}

	finalFilename := "/var/lib/settingsd/" + shaStr + ".json"
	err = os.Rename(filename, finalFilename)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Save error: %s", err.Error())})
		return
	}

	logger.Info("Uploaded %v to %v\n", file.Filename, finalFilename)
	url := location.Get(c)

	html := fmt.Sprintf("File successfully uploaded.<br/><a href=\"http://%s.%s/settings/\">Click here to view settings.</a>", shaStr, url.Host)
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(html))
}

func validSha(shaStr string) bool {
	matchFn := regexp.MustCompile("^[a-f0-9]{40}$").MatchString

	if !matchFn(shaStr) {
		return false
	}
	return true
}

func tmpFileName(prefix string, suffix string) string {
	randBytes := make([]byte, 16)
	rand.Read(randBytes)
	return filepath.Join(os.TempDir(), prefix+hex.EncodeToString(randBytes)+suffix)
}

func fileSha1(filePath string) (string, error) {
	var shaStr string

	file, err := os.Open(filePath)
	if err != nil {
		return shaStr, err
	}
	defer file.Close()

	hash := sha1.New()
	if _, err := io.Copy(hash, file); err != nil {
		return shaStr, err
	}

	hashInBytes := hash.Sum(nil)[:20]
	shaStr = hex.EncodeToString(hashInBytes)

	return shaStr, nil
}

// fakeAuthStatus
func fakeAuthStatus(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"username": "admin"})
}
