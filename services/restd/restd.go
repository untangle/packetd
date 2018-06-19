package restd

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/untangle/packetd/services/logger"
	"github.com/untangle/packetd/services/reports"
	"github.com/untangle/packetd/services/settings"
	"io/ioutil"
	"strconv"
	"strings"
)

var engine *gin.Engine
var appname = "restd"

// Startup is called to start the rest daemon
func Startup() {

	gin.DisableConsoleColor()
	gin.DefaultWriter = logger.NewLogWriter("restd")
	engine = gin.Default()

	// routes
	engine.GET("/ping", pingHandler)
	engine.POST("/reports/create_query", reportsCreateQuery)
	engine.GET("/reports/get_data/:query_id", reportsGetData)
	engine.GET("/settings/get_settings", getSettings)
	engine.GET("/settings/get_settings/*path", getSettings)
	engine.POST("/settings/set_settings", setSettings)
	engine.POST("/settings/set_settings/*path", setSettings)
	engine.DELETE("/settings/trim_settings", trimSettings)
	engine.DELETE("/settings/trim_settings/*path", trimSettings)

	// listen and serve on 0.0.0.0:8080
	engine.Run()

	logger.LogMessage(logger.LogInfo, appname, "The RestD engine has been started\n")
}

// Shutdown restd
func Shutdown() {

}

func pingHandler(c *gin.Context) {
	addHeaders(c)
	c.JSON(200, gin.H{
		"message": "pong",
	})
}

func reportsGetData(c *gin.Context) {
	addHeaders(c)

	// body, err := ioutil.ReadAll(c.Request.Body)
	// if err != nil {
	// 	c.JSON(200, gin.H{"error": err})
	// 	return
	// }
	queryStr := c.Param("query_id")
	// queryID, err := strconv.ParseUint(string(body), 10, 64)
	if queryStr == "" {
		c.JSON(200, gin.H{"error": "query_id not found"})
		return
	}
	queryID, err := strconv.ParseUint(queryStr, 10, 64)
	if err != nil {
		c.JSON(200, gin.H{"error": err})
		return
	}

	str, err := reports.GetData(queryID)
	if err != nil {
		c.JSON(200, gin.H{"error": err})
		return
	}

	c.String(200, str)
	return
}

func reportsCreateQuery(c *gin.Context) {
	addHeaders(c)

	body, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(200, gin.H{"error": err})
		return
	}
	q, err := reports.CreateQuery(string(body))
	if err != nil {
		c.JSON(200, gin.H{"error": err})
		return
	}
	str := fmt.Sprintf("%v", q.ID)
	logger.LogMessage(logger.LogDebug, appname, "CreateQuery(%s)\n", str)
	c.String(200, str)
	// c.JSON(200, gin.H{
	// 	"queryID": q.ID,
	// })
}

func getSettings(c *gin.Context) {
	addHeaders(c)

	var segments []string

	path := c.Param("path")

	if path == "" {
		segments = nil
	} else {
		segments = removeEmptyStrings(strings.Split(path, "/"))
	}

	jsonResult := settings.GetSettings(segments)
	c.JSON(200, jsonResult)
	return
}

func setSettings(c *gin.Context) {
	addHeaders(c)

	var segments []string
	path := c.Param("path")

	if path == "" {
		segments = nil
	} else {
		segments = removeEmptyStrings(strings.Split(path, "/"))
	}

	body, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(200, gin.H{"error": err})
		return
	}
	jsonResult := settings.SetSettingsParse(segments, body)
	c.JSON(200, jsonResult)
	return
}

func trimSettings(c *gin.Context) {
	addHeaders(c)

	var segments []string
	path := c.Param("path")

	if path == "" {
		segments = nil
	} else {
		segments = removeEmptyStrings(strings.Split(path, "/"))
	}

	jsonResult := settings.TrimSettings(segments)
	c.JSON(200, jsonResult)
	return
}

func removeEmptyStrings(strings []string) []string {
	b := strings[:0]
	for _, x := range strings {
		if x != "" {
			b = append(b, x)
		}
	}
	return b
}

func addHeaders(c *gin.Context) {
	// FIXME
	// This should be removed at some point
	// For development
	c.Header("Access-Control-Allow-Origin", "*")
	c.Header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE")
	c.Header("Access-Control-Allow-Headers", "X-Custom-Header")
}
