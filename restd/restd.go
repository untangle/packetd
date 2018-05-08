package restd

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/untangle/packetd/reports"
	"github.com/untangle/packetd/settings"
	"io/ioutil"
	"strconv"
	"strings"
)

var engine *gin.Engine

func pingHandler(c *gin.Context) {
	c.JSON(200, gin.H{
		"message": "pong",
	})
}

func reportsGetData(c *gin.Context) {
	// body, err := ioutil.ReadAll(c.Request.Body)
	// if err != nil {
	// 	c.JSON(200, gin.H{"error": err})
	// 	return
	// }
	queryStr := c.Param("query_id")
	// queryId, err := strconv.ParseUint(string(body), 10, 64)
	if queryStr == "" {
		c.JSON(200, gin.H{"error": "query_id not found"})
		return
	}
	queryId, err := strconv.ParseUint(queryStr, 10, 64)
	if err != nil {
		c.JSON(200, gin.H{"error": err})
		return
	}

	str, err := reports.GetData(queryId)
	if err != nil {
		c.JSON(200, gin.H{"error": err})
		return
	} else {
		c.String(200, str)
		return
	}
}

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
	str := fmt.Sprintf("%v", q.Id)
	fmt.Println("ID: ", str)
	c.String(200, str)
	// c.JSON(200, gin.H{
	// 	"queryId": q.Id,
	// })
}

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

func StartRestDaemon() {
	reports.ConnectDb()

	engine = gin.Default()

	// routes
	engine.GET("/ping", pingHandler)
	engine.POST("/reports/create_query", reportsCreateQuery)
	engine.GET("/reports/get_data/:query_id", reportsGetData)
	engine.GET("/settings/get_settings", getSettings)
	engine.GET("/settings/get_settings/*path", getSettings)
	engine.POST("/settings/set_settings", setSettings)
	engine.POST("/settings/set_settings/*path", setSettings)

	// listen and serve on 0.0.0.0:8080
	engine.Run()

	fmt.Println("Started RestD")
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
