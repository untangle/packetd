package restd

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/untangle/packetd/reports"
	"io/ioutil"
	"strconv"
)

var engine *gin.Engine

func pingHandler(c *gin.Context) {
	c.JSON(200, gin.H{
		"message": "pong",
	})
}

func reportsGetData(c *gin.Context) {
	body, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(200, gin.H{"error": err})
		return
	}
	queryId, err := strconv.ParseUint(string(body), 10, 64)
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

func StartRestDaemon() {
	reports.ConnectDb()

	engine = gin.Default()

	// routes
	engine.GET("/ping", pingHandler)
	engine.POST("/reports/create_query", reportsCreateQuery)
	engine.POST("/reports/get_data", reportsGetData)

	// listen and serve on 0.0.0.0:8080
	engine.Run()

	fmt.Println("Started RestD")
}
