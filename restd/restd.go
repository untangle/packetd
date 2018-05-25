package restd

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/untangle/packetd/reports"
	"github.com/untangle/packetd/settings"
	"github.com/untangle/packetd/support"
	"io/ioutil"
	"strconv"
	"strings"
)

var engine *gin.Engine
var appname = "restd"

//-----------------------------------------------------------------------------

func pingHandler(c *gin.Context) {
	c.JSON(200, gin.H{
		"message": "pong",
	})
}

//-----------------------------------------------------------------------------

func reportsGetData(c *gin.Context) {
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

//-----------------------------------------------------------------------------

func reportsCreateQuery(c *gin.Context) {
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
	support.LogMessage(support.LogDebug, appname, "CreateQuery(%s)\n", str)
	c.String(200, str)
	// c.JSON(200, gin.H{
	// 	"queryID": q.ID,
	// })
}

//-----------------------------------------------------------------------------

func getSettings(c *gin.Context) {
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

//-----------------------------------------------------------------------------

func setSettings(c *gin.Context) {
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

//-----------------------------------------------------------------------------

func trimSettings(c *gin.Context) {
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

//-----------------------------------------------------------------------------

// StartRestDaemon is called to start the rest daemon
func StartRestDaemon() {
	reports.ConnectDb()

	gin.DisableConsoleColor()
	gin.DefaultWriter = support.NewLogWriter("restd")
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

	support.LogMessage(support.LogInfo, appname, "The RestD engine has been started\n")
}

//-----------------------------------------------------------------------------

func removeEmptyStrings(strings []string) []string {

	b := strings[:0]
	for _, x := range strings {
		if x != "" {
			b = append(b, x)
		}
	}
	return b
}

//-----------------------------------------------------------------------------
