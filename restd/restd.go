package restd

import (
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/untangle/packetd/reports"
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
	path := c.Param("path")
	jsonObject, err := readSettingsFile()
	if err != nil {
		c.JSON(200, gin.H{"error": err})
		return
	}
	if path != "" {
		segments := removeEmptyStrings(strings.Split(path, "/"))
		lastValue := ""
		for _, value := range segments {
			if value != "" {
				j, ok := jsonObject.(map[string]interface{})
				if ok {
					jsonObject = j[value]
					if jsonObject == nil {
						c.JSON(200, gin.H{"error": "Attribute " + value + " not found in JSON object"})
						return
					}
				} else {
					c.JSON(200, gin.H{"error": "Map " + lastValue + " not found in JSON object"})
					return
				}
			}
			lastValue = value
		}
	}

	c.JSON(200, jsonObject)
	return
}

func setSettings(c *gin.Context) {
	path := c.Param("path")
	var bodyString []byte

	bodyString, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(200, gin.H{"error": err})
		return
	}

	var jsonObject interface{}
	var bodyJsonObject interface{}
	var iterJsonObject map[string]interface{}
	var jsonObjectCast map[string]interface{}
	var ok bool

	err = json.Unmarshal(bodyString, &bodyJsonObject)
	if err != nil {
		bodyJsonObject = nil
	}

	if path != "" {
		jsonObject, err = readSettingsFile()
		if err != nil {
			c.JSON(200, gin.H{"error": err})
			return
		}

		segments := removeEmptyStrings(strings.Split(path, "/"))

		jsonObjectCast, ok = jsonObject.(map[string]interface{})
		if !ok {
			c.JSON(200, gin.H{"error": "Invalid settings JSON object", "json": jsonObject})
			return
		}
		iterJsonObject = jsonObjectCast

		for i, value := range segments {
			//if this is the last value, set and break
			if i == len(segments)-1 {
				if bodyJsonObject != nil {
					iterJsonObject[value] = bodyJsonObject
				} else {
					iterJsonObject[value] = string(bodyString)
				}
				break
			}

			// otherwise recurse down object
			// 3 cases:
			// if json[foo] does not exist, create a map
			// if json[foo] exists and is a map, recurse
			// if json[foo] exists and is not a map (its some value)
			//    in this case we overwrite with a map, and recurse

			if iterJsonObject[value] == nil {
				newMap := make(map[string]interface{})
				iterJsonObject[value] = newMap
				iterJsonObject = newMap
			} else {
				jsonObjectCast, ok = iterJsonObject[value].(map[string]interface{})
				iterJsonObject[value] = make(map[string]interface{})
				if ok {
					iterJsonObject[value] = jsonObjectCast
					iterJsonObject = jsonObjectCast
				} else {
					newMap := make(map[string]interface{})
					iterJsonObject[value] = newMap
					iterJsonObject = newMap
				}
			}
		}
	} else {
		if bodyJsonObject == nil {
			c.JSON(200, gin.H{"error": "Invalid JSON"})
			return
		}

		// if the path is empty, just use the whole body
		jsonObject = bodyJsonObject
	}

	// Marshal it back to a string (with ident)
	var jsonString []byte
	jsonString, err = json.MarshalIndent(jsonObject, "", "  ")
	if err != nil {
		c.JSON(200, gin.H{"error": err})
		return
	}

	err = ioutil.WriteFile("/etc/config/settings.json", jsonString, 0644)
	if err != nil {
		c.JSON(200, gin.H{"error": err})
		return
	}
	c.JSON(200, gin.H{"result": "OK"})
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

func readSettingsFile() (interface{}, error) {
	raw, err := ioutil.ReadFile("/etc/config/settings.json")
	if err != nil {
		return nil, err
	}
	var jsonObject interface{}
	err = json.Unmarshal(raw, &jsonObject)
	if err != nil {
		return nil, err
	}
	return jsonObject, nil
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
